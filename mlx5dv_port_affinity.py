#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Liu, Changcheng <changcheng.liu@aliyun.com>

import os
import sys
import time
import datetime
import argparse
import subprocess

try:
    from pyverbs.device import Context
    from pyverbs.pd import PD
    from pyverbs.cq import CQ
    from pyverbs.mr import MR
    from pyverbs.addr import AH
    from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
    from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
    from pyverbs.cmid import CMID, AddrInfo, CMEventChannel, CMEvent, ConnParam
    from pyverbs.wr import SGE, SendWR
    from pyverbs.pyverbs_error import PyverbsRDMAError
    import pyverbs.cm_enums as ce
    import pyverbs.enums as e
except ImportError as ex:
    print(f'Fail to import {ex}')

os.environ["PATH"] = os.path.dirname("/opt/mellanox/ethtool/sbin/ethtool") + os.pathsep + os.environ["PATH"]

class ArgsParser(object):
    def __init__(self):
        self.args = None

    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--addr',
                            help='server bind ip addr or client connect to server ip address')
        parser.add_argument('--server', action = 'store_true',
                            help = 'play server role')
        parser.add_argument('--port',
                            help = 'server port', type = str, default = "51216")
        parser.add_argument('--time',
                            help = 'timeout', type = int, default = 60)
        ns, args = parser.parse_known_args()
        self.args = vars(ns)

def get_tx_packets_phy(slave_nic):
    cmd = "ethtool -S " + slave_nic + " | awk '/tx_packets_phy:/{print$2}'"
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, shell=True,
                               executable="/bin/bash")
    tx_packets_phy, error = process.communicate()
    tx_packets_phy = tx_packets_phy.strip()
    if isinstance(tx_packets_phy, bytes):
        tx_packets_phy = tx_packets_phy.decode()

    return int(tx_packets_phy)

class LAGUDResource:
    def __init__(self, lag_dev_name = "mlx5_bond_0", ib_port = 1,
                 print_fun = print):
        self.print_fun = print_fun

        self.lag_dev_name = lag_dev_name
        self.port_num  = ib_port
        self.ctx       = None
        self.pd        = None
        self.cq        = None
        self.mr        = None

        self.ud_qp     = None

        self.local_qp_num  = 0
        self.remote_qp_num = 0

        self.get_lag_slaves_name()

        self.init_resources()

    def init_resources(self):
        self.print_fun("Init RDMA resources: lag dev %s, "
                       "bond master %s, bond slaves: %s"
                       %(self.lag_dev_name, self.bond_master,
                         ' '.join(self.bond_slaves)))
        self.open_context()
        self.alloc_pd()
        self.create_cq()
        self.reg_mr()

        self.create_ud_qp()
        self.ud_qp_rst2init()
        self.ud_qp_init2rtr()
        self.ud_qp_rtr2rts()

    def open_context(self):
        self.ctx = Context(name = self.lag_dev_name)

    def alloc_pd(self):
        self.pd = PD(self.ctx)

    def create_cq(self):
        self.cq = CQ(self.ctx, cqe = 10)

    def reg_mr(self):
        self.mr = MR(self.pd, 250, e.IBV_ACCESS_LOCAL_WRITE)

    def create_ud_qp(self):
        qp_cap = QPCap(max_send_wr = 5, max_recv_wr = 5,
                       max_send_sge = 1, max_recv_sge = 1)
        qp_init_attr = QPInitAttr(qp_type = e.IBV_QPT_UD,
                                  scq = self.cq, rcq = self.cq,
                                  cap = qp_cap)
        self.ud_qp = QP(self.pd, qp_init_attr)
        self.local_qp_num = self.ud_qp.qp_num

    def ud_qp_rst2init(self):
        qp_attr = QPAttr()

        qp_attr.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE
        qp_attr.pkey_index = 0
        qp_attr.qkey = 0x11111111
        qp_attr.port_num = self.port_num

        self.ud_qp.to_init(qp_attr)

    def ud_qp_init2rtr(self):
        qp_attr, _ = self.ud_qp.query(e.IBV_QP_STATE | e.IBV_QP_PORT)

        qp_attr.rq_psn = 0
        qp_attr.path_mtu = e.IBV_MTU_1024
        qp_attr.qp_state = e.IBV_QPS_RTR

        self.ud_qp.to_rtr(qp_attr)

    def ud_qp_rtr2rts(self):
        qp_attr, _ = self.ud_qp.query(e.IBV_QP_STATE)

        qp_attr.qp_state = e.IBV_QPS_RTS
        qp_attr.sq_psn = 0;

        self.ud_qp.to_rts(qp_attr)

    def poll_cq(self, count = 1, polling_timeout = 25):
        start = datetime.datetime.now()

        while count > 0 and (datetime.datetime.now() - start).seconds < polling_timeout:
            nc, wcs = self.cq.poll(num_entries = 1)

            if nc:
                for wc in wcs:
                    if wc.status != e.IBV_WC_SUCCESS:
                        print(f'Polled: {wc}')
                        raise PyverbsRDMAError('Completion status is '
                                               f'{cqe_status_to_str(wc.status)}')

            count -= nc

        if count:
            raise PyverbsRDMAError('Fail to poll, got timeout')

    def post_send(self, ah):
        sge = SGE(self.mr.buf, 250, self.mr.lkey)
        swr = SendWR(num_sge = 1, sg = [sge])
        swr.set_wr_ud(ah, self.remote_qp_num, 0x11111111)

        self.ud_qp.post_send(swr)

    def get_lag_slaves_name(self):
        cmd = "ls -l /sys/class/infiniband/" + self.lag_dev_name + \
              "/device/net/*/master | rev | cut -d '/' -f 1 | rev"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=True,
                                   executable="/bin/bash")
        bond_master, error = process.communicate()
        bond_master = bond_master.strip()
        if isinstance(bond_master, bytes):
            bond_master = bond_master.decode()

        cmd = "cat /sys/class/net/" + bond_master + "/bonding/slaves"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=True,
                                   executable="/bin/bash")
        bond_slaves, error = process.communicate()
        bond_slaves = bond_slaves.strip()
        if isinstance(bond_slaves, bytes):
            bond_slaves = bond_slaves.decode()

        self.bond_master = bond_master
        self.bond_slaves = bond_slaves.split()
        self.bond_slaves.sort()

class LAGUDTrafficTest:
    def __init__(self, server_ip , service_port = "51216", is_server = False, timeout = 60, print_fun = print):
        self.print_fun = print_fun
        self.timeout   = timeout

        self.server_ip    = server_ip
        self.service_port = service_port
        self.is_server = is_server

        self.listen_id = None
        self.id        = None

        self.init_connection()

        self.init_ud_rsc()

        self.establish_connection()

        self.run_traffic()

        self.verify_traffic_counter()

        self.disconnect()

    def init_ud_rsc(self):
        if self.is_server == True:
            self.ud_rsc = LAGUDResource(lag_dev_name = self.listen_id.dev_name,
                                        ib_port = self.listen_id.port_num)
        else:
            self.ud_rsc = LAGUDResource(lag_dev_name = self.id.dev_name,
                                        ib_port = self.id.port_num)

    def init_connection(self):
        self.event_ch  = CMEventChannel()
        self.create_cmid()

        if self.is_server == True:
            self.ai = AddrInfo(src = self.server_ip,
                               src_service = self.service_port,
                               port_space = ce.RDMA_PS_TCP,
                               flags = ce.RAI_PASSIVE)
            self.init_server_cm()
        else:
            self.ai = AddrInfo(dst = self.server_ip,
                               dst_service = self.service_port,
                               port_space = ce.RDMA_PS_TCP)
            self.init_client_cm()

    def create_cmid(self):
        if self.is_server == True:
            self.listen_id = CMID(creator = self.event_ch,
                                  port_space=ce.RDMA_PS_TCP)
        else:
            self.id = CMID(creator = self.event_ch,
                           port_space=ce.RDMA_PS_TCP)

    def init_client_cm(self):
        self.id.resolve_addr(self.ai)
        cm_event = CMEvent(self.event_ch)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_ADDR_RESOLVED
        cm_event.ack_cm_event()

        self.id.resolve_route()
        cm_event = CMEvent(self.event_ch)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_ROUTE_RESOLVED
        cm_event.ack_cm_event()

    def init_server_cm(self):
        self.listen_id.bind_addr(self.ai)

    def establish_connection(self):
        if self.is_server == True:
            self.listen_connect()

            self.wait_conn_req()

            self.create_ah_cache()

            self.accept_conn()

            self.wait_conn_establish()
        else:
            self.client_connect()

            while self.wait_conn_resp() != 0:
                self.id.close()

                self.create_cmid()
                self.init_client_cm()

                time.sleep(2)

                self.client_connect()

            self.client_establish()

    def disconnect(self):
        if self.is_server == True:
            self.server_disconnect()

        self.wait_discon_event()

    def create_ah_cache(self):
        qp_attr, _ = self.id.init_qp_attr(e.IBV_QPS_RTR)
        self.ah_cache = AH(self.ud_rsc.pd, attr = qp_attr.ah_attr)

    def client_connect(self):
        conn_param = ConnParam(qp_num = self.ud_rsc.local_qp_num, data_len = 56)
        private_data = self.ud_rsc.local_qp_num.to_bytes(4, byteorder='little')
        conn_param.set_private_data(private_data)
        self.id.connect(conn_param)

    def wait_conn_resp(self):
        cm_event = CMEvent(self.event_ch)

        if cm_event.event_type == ce.RDMA_CM_EVENT_REJECTED:
            cm_event.ack_cm_event()
            return 1
        else:
            assert cm_event.event_type == ce.RDMA_CM_EVENT_CONNECT_RESPONSE
            private_data = cm_event.private_data
            self.ud_rsc.remote_qp_num = int.from_bytes(private_data[:3], 'little')
            cm_event.ack_cm_event()
            return 0

    def client_establish(self):
        self.id.establish()

    def server_disconnect(self):
        self.id.disconnect()

    def wait_discon_event(self):
        cm_event = CMEvent(self.event_ch)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_DISCONNECTED

    def listen_connect(self):
        self.listen_id.listen(backlog = 1)

    def wait_conn_req(self):
        cm_event = CMEvent(self.event_ch)
        self.id = CMID(creator = cm_event, listen_id = self.listen_id)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_CONNECT_REQUEST

        private_data = cm_event.private_data
        self.ud_rsc.remote_qp_num = int.from_bytes(private_data[:3], 'little')
        cm_event.ack_cm_event()

    def accept_conn(self):
        conn_param = ConnParam(qp_num = self.ud_rsc.local_qp_num, data_len = 56)
        private_data = self.ud_rsc.local_qp_num.to_bytes(4, byteorder='little')
        conn_param.set_private_data(private_data)
        self.id.accept(conn_param)

    def wait_conn_establish(self):
        cm_event = CMEvent(self.event_ch)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_ESTABLISHED

        cm_event.ack_cm_event()

    def init_traffic_counter(self):
        self.packets_phy1_start = get_tx_packets_phy(self.ud_rsc.bond_slaves[0])
        self.packets_phy2_start = get_tx_packets_phy(self.ud_rsc.bond_slaves[1])

        self.packets_phy1_update = 0
        self.packets_phy2_update = 0

    def update_traffic_counter(self):
        _, active_port_num = Mlx5QP.query_lag_port(self.ud_rsc.ud_qp)
        if active_port_num == 1 :
            self.packets_phy1_update += 1
        else :
            self.packets_phy2_update += 1

    def verify_traffic_counter(self):
        if self.is_server != True:
            return

        packets_phy1_end = get_tx_packets_phy(self.ud_rsc.bond_slaves[0])
        packets_phy2_end = get_tx_packets_phy(self.ud_rsc.bond_slaves[1])

        self.print_fun("phy1 inc:  %d" %self.packets_phy1_update)
        self.print_fun("phy2 inc:  %d" %self.packets_phy2_update)
        self.print_fun("phy1 init: %d" %self.packets_phy1_start)
        self.print_fun("phy2 init: %d" %self.packets_phy2_start)
        self.print_fun("phy1 end:  %d" %packets_phy1_end)
        self.print_fun("phy2 end:  %d" %packets_phy2_end)

        #It checkes the active_port_num after the message have been sent.
        #In case of the sent port does not aligh with active_port_num,
        #it checks that packets number changes more than half of the updated packets.
        assert packets_phy1_end - self.packets_phy1_start >= \
               self.packets_phy1_update / 2
        assert packets_phy2_end - self.packets_phy2_start >= \
               self.packets_phy2_update / 2

    def run_traffic(self):
        if self.is_server != True:
            return

        Mlx5QP.modify_lag_port(self.ud_rsc.ud_qp, 1)
        affinity_port_num, active_port_num = Mlx5QP.query_lag_port(self.ud_rsc.ud_qp)
        assert affinity_port_num == 1

        start_time = datetime.datetime.now()
        self.init_traffic_counter()

        while (datetime.datetime.now() - start_time).seconds < self.timeout :
            self.ud_rsc.post_send(self.ah_cache)
            self.ud_rsc.poll_cq()
            self.update_traffic_counter()

def main():
    parser = ArgsParser()
    parser.parse_args()

    LAGUDTrafficTest(server_ip = parser.args['addr'], is_server = parser.args['server'], service_port = parser.args['port'], timeout = parser.args['time'])

if __name__ == "__main__":
    main()
