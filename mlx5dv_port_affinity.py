#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Liu, Changcheng <changcheng.liu@aliyun.com>

import sys
import time
import datetime
import argparse
import subprocess

from pyverbs.device import Context
from pyverbs.pd import PD
from pyverbs.cq import CQ
from pyverbs.mr import MR
from pyverbs.addr import AH
from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
from pyverbs.cmid import CMID, AddrInfo, CMEventChannel, CMEvent, ConnParam
from pyverbs.wr import SGE, SendWR
import pyverbs.cm_enums as ce
import pyverbs.enums as e
from pyverbs.pyverbs_error import PyverbsRDMAError

class ArgsParser(object):
    def __init__(self):
        self.args = None

    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('--addr',
                            help='server bind ip addr or client connect to server ip address')
        parser.add_argument('--server', action='store_true',
                            help='play server role')
        parser.add_argument('--port',
                            help='server port', type=int, default=5126)
        ns, args = parser.parse_known_args()
        self.args = vars(ns)

class memory_domain:
    def __init__(self):
        self.ctx = None
        self.cq  = None
        self.qp  = None

        self.mr   = None

        self.local_qp_num  = 0
        self.remote_qp_num = 0

        self.qp_attr       = None
        self.qp_attr_mask  = 0

class cm_context:
    def __init__(self):
        self.event_ch  = CMEventChannel()
        self.listen_id = None
        self.id        = None

        self.bond_master = None
        self.bond_slaves = None

        self.is_server   = False
        self.server_addr = None
        self.server_port = "51216"
        self.ai          = None

        self.md          = memory_domain()

    def set_addrinfo(self):
        if self.is_server == True:
            self.ai = AddrInfo(src = self.server_addr,
                               src_service = self.server_port,
                               port_space = ce.RDMA_PS_TCP,
                               flags = ce.RAI_PASSIVE)
        else:
            self.ai = AddrInfo(dst = self.server_addr,
                               dst_service = self.server_port,
                               port_space = ce.RDMA_PS_TCP)

    def create_cmid(self):
        if self.is_server == True:
            self.listen_id = CMID(creator = self.event_ch,
                                  port_space=ce.RDMA_PS_TCP)
        else:
            self.id = CMID(creator = self.event_ch,
                           port_space=ce.RDMA_PS_TCP)

    def get_slave_interface_name(self):
        cmd = "ls -l /sys/class/infiniband/" + self.id.dev_name + "/device/net/*/master | rev | cut -d '/' -f 1 | rev"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, executable="/bin/bash")
        bond_master, error = process.communicate()
        bond_master = bond_master.strip()
        if isinstance(bond_master, bytes):
            bond_master = bond_master.decode()

        cmd = "cat /sys/class/net/" + bond_master + "/bonding/slaves"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, executable="/bin/bash")
        bond_slaves, error = process.communicate()
        bond_slaves = bond_slaves.strip()
        if isinstance(bond_slaves, bytes):
            bond_slaves = bond_slaves.decode()

        self.bond_master = bond_master
        self.bond_slaves = bond_slaves.split()
        self.bond_slaves.sort()

    def get_tx_packets_phy(self, slave_nic):
        cmd = "ethtool -S " + slave_nic + " | awk '/tx_packets_phy:/{print$2}'"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, executable="/bin/bash")
        tx_packets_phy, error = process.communicate()
        tx_packets_phy = tx_packets_phy.strip()
        if isinstance(tx_packets_phy, bytes):
            tx_packets_phy = tx_packets_phy.decode()

        return int(tx_packets_phy)

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

    def init_md(self):
        if (self.is_server == True):
            self.md.ctx = Context(name = self.listen_id.dev_name)
        else:
            self.md.ctx = Context(name = self.id.dev_name)

        self.md.pd = PD(self.md.ctx)
        self.md.cq = CQ(self.md.ctx, 3, None, None, 0)
        self.md.mr = MR(self.md.pd, 520, e.IBV_ACCESS_LOCAL_WRITE)

    def ud_qp_rst2init(self):
        qp_attr = QPAttr()
        qp_attr.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE
        qp_attr.pkey_index = 0
        qp_attr.qkey = 0x11111111
        qp_attr.port_num = 1
        self.md.qp.to_init(qp_attr)

    def ud_qp_init2rtr(self):
        qp_attr, _ = self.md.qp.query(e.IBV_QP_STATE | e.IBV_QP_PORT)

        qp_attr.rq_psn = 0
        qp_attr.path_mtu = e.IBV_MTU_1024
        qp_attr.qp_state = e.IBV_QPS_RTR

        self.md.qp.to_rtr(qp_attr)

    def ud_qp_rtr2rts(self):
        qp_attr, _ = self.md.qp.query(e.IBV_QP_STATE)

        qp_attr.qp_state = e.IBV_QPS_RTS
        qp_attr.sq_psn = 0;

        self.md.qp.to_rts(qp_attr)

    def create_ud_qp(self):
        qp_cap = QPCap(max_send_wr = 3, max_recv_wr = 3,
                       max_send_sge = 1, max_recv_sge = 1)
        qp_init_attr = QPInitAttr(qp_type = e.IBV_QPT_UD,
                                  scq = self.md.cq,
                                  rcq = self.md.cq,
                                  cap = qp_cap)
        self.md.qp = QP(self.md.pd, qp_init_attr)
        self.md.local_qp_num = self.md.qp.qp_num

    def create_ah_cache(self):
        qp_attr, _ = self.id.init_qp_attr(e.IBV_QPS_RTR)
        self.ah_cache = AH(self.md.pd, attr = qp_attr.ah_attr)

    def client_connect(self):
        conn_param = ConnParam(resources = 2, depth = 2, retry = 5, rnr_retry = 5, qp_num = self.md.local_qp_num, data_len = 56)
        private_data = self.md.local_qp_num.to_bytes(4, byteorder='little')
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
            self.md.remote_qp_num = int.from_bytes(private_data[:3], 'little')
            cm_event.ack_cm_event()
            return 0

    def client_establish(self):
        self.id.establish()

    def server_disconnect(self):
        self.id.disconnect()

    def wait_discon_event(self):
        cm_event = CMEvent(self.event_ch)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_DISCONNECTED

    def run_client(self):
        self.client_connect()

        while self.wait_conn_resp() != 0:
            self.id.close()

            self.create_cmid()
            self.init_client_cm()

            time.sleep(2)

            self.client_connect()

        self.client_establish()

        self.wait_discon_event()

    def listen_connect(self):
        self.listen_id.listen(backlog = 1)

    def wait_conn_req(self):
        cm_event = CMEvent(self.event_ch)
        self.id = CMID(creator = cm_event, listen_id = self.listen_id)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_CONNECT_REQUEST

        private_data = cm_event.private_data
        self.md.remote_qp_num = int.from_bytes(private_data[:3], 'little')
        cm_event.ack_cm_event()

    def accept_conn(self):
        conn_param = ConnParam(resources = 2, depth = 2, retry = 5, rnr_retry = 5, qp_num = self.md.local_qp_num, data_len = 56)
        private_data = self.md.local_qp_num.to_bytes(4, byteorder='little')
        conn_param.set_private_data(private_data)
        self.id.accept(conn_param)

    def wait_conn_establish(self):
        cm_event = CMEvent(self.event_ch)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_ESTABLISHED

        cm_event.ack_cm_event()

    def server_post_send(self):
        sge = SGE(self.md.mr.buf, 520, self.md.mr.lkey)
        swr = SendWR(opcode = e.IBV_WR_SEND, num_sge = 1, sg = [sge], send_flags=e.IBV_SEND_SIGNALED)
        swr.set_wr_ud(self.ah_cache, self.md.remote_qp_num, 0x11111111)

        self.md.qp.post_send(swr)

    def poll(self, count = 1, polling_timeout = 25):
        start = datetime.datetime.now()

        while count > 0 and (datetime.datetime.now() - start).seconds < polling_timeout:
            nc, wcs = self.md.cq.poll(num_entries = 1)

            if nc:
                for wc in wcs:
                    if wc.status != e.IBV_WC_SUCCESS:
                        print(f'Polled: {wc}')
                        raise PyverbsRDMAError('Completion status is '
                                               f'{cqe_status_to_str(wc.status)}')

            count -= nc

        if count:
            raise PyverbsRDMAError('Fail to poll, got timeout')

    def run_server(self):
        self.listen_connect()

        self.wait_conn_req()

        self.create_ah_cache()

        self.accept_conn()

        self.wait_conn_establish()

        self.get_slave_interface_name()

        start_time = datetime.datetime.now()

        Mlx5QP.modify_lag_port(self.md.qp, 1)

        affinity_port_num, active_port_num = Mlx5QP.query_lag_port(self.md.qp)
        assert affinity_port_num == 1

        tx_packets_phy1_start = self.get_tx_packets_phy(self.bond_slaves[0])
        tx_packets_phy2_start = self.get_tx_packets_phy(self.bond_slaves[1])

        tx_packets_phy1_update = 0
        tx_packets_phy2_update = 0
        while (datetime.datetime.now() - start_time).seconds < 60 :
            self.server_post_send()
            self.poll()

            _, active_port_num = Mlx5QP.query_lag_port(self.md.qp)
            if active_port_num == 1 :
                tx_packets_phy1_update += 1
            else :
                tx_packets_phy2_update += 1

        tx_packets_phy1_end = self.get_tx_packets_phy(self.bond_slaves[0])
        tx_packets_phy2_end = self.get_tx_packets_phy(self.bond_slaves[1])

        print("phy1 inc: %d" %tx_packets_phy1_update)
        print("phy2 inc: %d" %tx_packets_phy2_update)
        print("phy1 init: %d" %tx_packets_phy1_start)
        print("phy2 init: %d" %tx_packets_phy2_start)
        print("phy1 end: %d" %tx_packets_phy1_end)
        print("phy2 end: %d" %tx_packets_phy2_end)

        #It checkes the active_port_num after the message have been sent.
        #In case of the sent port does not aligh with active_port_num,
        #it checks that packets number changes more than half of the updated packets.
        assert tx_packets_phy1_end - tx_packets_phy1_start >= tx_packets_phy1_update / 2
        assert tx_packets_phy2_end - tx_packets_phy2_start >= tx_packets_phy2_update / 2

        self.server_disconnect()
        self.wait_discon_event()

def main():
    parser = ArgsParser()
    parser.parse_args()

    cm_ctx = cm_context()

    cm_ctx.is_server   = parser.args['server']
    cm_ctx.server_addr = parser.args['addr']
    cm_ctx.port        = parser.args['port']

    cm_ctx.set_addrinfo()
    cm_ctx.create_cmid()

    if cm_ctx.is_server == True:
         cm_ctx.init_server_cm()
    else:
         cm_ctx.init_client_cm()

    cm_ctx.init_md()
    cm_ctx.create_ud_qp()
    cm_ctx.ud_qp_rst2init()
    cm_ctx.ud_qp_init2rtr()
    cm_ctx.ud_qp_rtr2rts()

    if cm_ctx.is_server == True:
        cm_ctx.run_server()
    else:
        cm_ctx.run_client()

if __name__ == "__main__":
    main()
