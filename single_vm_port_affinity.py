#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Liu, Changcheng <changcheng.liu@aliyun.com>

import os
import sys
import datetime
import argparse
import subprocess

try:
    from pyverbs.device import Context
    from pyverbs.pd import PD
    from pyverbs.cq import CQ
    from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
    from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
    from pyverbs.mr import MR
    from pyverbs.wr import SGE, SendWR, RecvWR
    import pyverbs.enums as e

    from pyverbs.pyverbs_error import PyverbsRDMAError
except ImportError as ex:
    print(f'Fail to import {ex}')

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

class ArgsParser(object):
    def __init__(self):
        self.args = None

    def parse_args(self):
        parser = argparse.ArgumentParser()
        parser.add_argument('-s', dest = "send_dev", help = "IB device", default='mlx5_bond_0')
        parser.add_argument('-r', dest = "recv_dev", help = "IB device", default='mlx5_bond_1')
        parser.add_argument('-t', dest = "timeout", help = "timeout in seconds", type = int, default = 10)
        ns, args = parser.parse_known_args()
        self.args = vars(ns)

class RCResources():
    def __init__(self, dev_name, print_fun=print):
        self.msg_size  = 520
        self.print_fun = print_fun

        self.device    = dev_name
        self.ctx       = None
        self.pd        = None
        self.mr        = None
        self.cq        = None
        self.qp        = None

        self.init_resources()

    def init_resources(self):
        self.print_fun('Init RDMA resources')
        self.open_context()
        self.alloc_pd()
        self.create_cq()
        self.reg_mr()
        self.create_qp()

    def open_context(self):
        self.ctx = Context(name = self.device)

    def alloc_pd(self):
        self.pd = PD(self.ctx)

    def create_cq(self):
        self.cq = CQ(self.ctx, cqe = 10)

    def poll(self, count = 1, polling_timeout = 25):
        start = datetime.datetime.now()

        while count > 0 and (datetime.datetime.now() - start).seconds < polling_timeout:
            nc, wcs = self.cq.poll(num_entries = 1)

            if nc:
                for wc in wcs:
                    if wc.status != e.IBV_WC_SUCCESS:
                        self.print_func(f'Polled: {wc}')
                        raise PyverbsRDMAError('Completion status is '
                                               f'{cqe_status_to_str(wc.status)}')

            count -= nc

        if count:
            raise PyverbsRDMAError('Fail to poll, got timeout')


    def reg_mr(self):
        mr_size = self.msg_size
        self.mr = MR(self.pd, mr_size, e.IBV_ACCESS_LOCAL_WRITE)

    def qp_rst2init(self):
        qp_attr = QPAttr()
        qp_attr.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE
        qp_attr.port_num = 1
        self.qp.to_init(qp_attr)

    def qp_init2rtr(self, remote_qp):
        qp_attr, _ = self.qp.query(e.IBV_QP_STATE | e.IBV_QP_CUR_STATE |
                                   e.IBV_QP_PKEY_INDEX | e.IBV_QP_PORT |
                                   e.IBV_QP_AV)

        qpa_ah_attr = qp_attr.ah_attr

        qpa_ah_attr.dlid = remote_qp.ctx.query_port(1).lid
        qpa_ah_attr.sgid_index = 1
        qpa_ah_attr.dgid = remote_qp.ctx.query_gid(1, index = 1).gid

        qp_attr.ah_attr = qpa_ah_attr

        qp_attr.rq_psn = 0
        qp_attr.max_dest_rd_atomic = 1
        qp_attr.min_rnr_timer = 0x12
        qp_attr.path_mtu = e.IBV_MTU_1024
        qp_attr.qp_state = e.IBV_QPS_RTR
        qp_attr.dest_qp_num = remote_qp.qp_num

        self.qp.to_rtr(qp_attr)

    def qp_rtr2rts(self):
        qp_attr, _ = self.qp.query(e.IBV_QP_STATE | e.IBV_QP_CUR_STATE)

        qp_attr.qp_state = e.IBV_QPS_RTS

        qp_attr.sq_psn = 0
        qp_attr.max_rd_atomic = 1
        qp_attr.timeout = 0x12
        qp_attr.retry_cnt = 7
        qp_attr.rnr_retry = 7

        self.qp.to_rts(qp_attr)

    def create_qp_cap(self):
        return QPCap(max_send_wr=1, max_recv_wr=1,
                     max_send_sge=1, max_recv_sge=1)

    def create_qp_init_attr(self):
        qp_cap = self.create_qp_cap()

        return QPInitAttr(qp_type = e.IBV_QPT_RC,
                          scq = self.cq,
                          rcq = self.cq,
                          cap = qp_cap,
                          sq_sig_all = 1)

    def create_qp(self):
        qp_init_attr = self.create_qp_init_attr()
        self.qp = QP(self.pd, qp_init_attr)
        self.qp_rst2init()

    @property
    def qp_num(self):
        return self.qp.qp_num

class RCTrafficTest():
    def __init__(self, send_dev = 'mlx5_bond_0', recv_dev = 'mlx5_bond_1', timeout = 25, print_fun = print):
        self.send_dev = send_dev 
        self.recv_dev = recv_dev 
        self.timeout = timeout
        self.print_fun = print_fun
        self.print_fun('================ Start RC Traffic Test ================')

        try:
            self.get_slave_interface_name()
            self.create_resources()
            self.connect_qps()

            self.start_time = datetime.datetime.now()

            self.init_tx_packets()

            self.rc_traffic()

            self.verify_tx_packets()

        except Exception as ex:
            raise ex

    def is_not_timeout(self):
        return (datetime.datetime.now() - self.start_time).seconds < self.timeout

    def get_slave_interface_name(self):
        cmd = "ls -l /sys/class/infiniband/" + self.send_dev + "/device/net/*/master | rev | cut -d '/' -f 1 | rev"
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
        assert len(self.bond_slaves) == 2

        self.print_fun('rdma device: ' + self.send_dev + ', ' +
                       'bond master : ' +  self.bond_master + ', ' +
                       'bond slaves : ' + self.bond_slaves[0] + ' & ' +
                       self.bond_slaves[1])

    def get_inteface_tx_packets_phy(self, ifc_name):
        cmd = "ethtool -S " + ifc_name + " | awk '/tx_packets_phy:/{print$2}'"
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, executable="/bin/bash")
        tx_packets_phy, error = process.communicate()

        tx_packets_phy = tx_packets_phy.strip()
        if isinstance(tx_packets_phy, bytes):
            tx_packets_phy = tx_packets_phy.decode()

        return int(tx_packets_phy)

    def post_recv(self):
        sge = SGE(self.recv_qp.mr.buf, self.recv_qp.msg_size, self.recv_qp.mr.lkey)
        rwr = RecvWR(wr_id = 0, num_sge = 1, sg = [sge])

        self.recv_qp.qp.post_recv(rwr)

    def poll_recv(self):
        self.recv_qp.poll()

    def post_send(self, val = 0xcafebeef):
        send_val = int(val).to_bytes(4, byteorder = 'little')
        self.send_qp.mr.write(send_val, length = 4, offset = 0)

        sge = SGE(self.send_qp.mr.buf, self.send_qp.msg_size, self.send_qp.mr.lkey)
        swr = SendWR(wr_id = 0, opcode = e.IBV_WR_SEND, num_sge = 1, sg = [sge], send_flags=e.IBV_SEND_SIGNALED)

        self.send_qp.qp.post_send(swr)

    def poll_send(self):
        self.send_qp.poll()

    def init_tx_packets(self):
        self.tx_packets_phy1 = 0
        self.tx_packets_phy2 = 0

        self.tx_packets_phy1_init = self.get_inteface_tx_packets_phy(self.bond_slaves[0])
        self.tx_packets_phy2_init = self.get_inteface_tx_packets_phy(self.bond_slaves[1])

    def verify_tx_packets(self):
        tx_packets_phy1_now = self.get_inteface_tx_packets_phy(self.bond_slaves[0])
        tx_packets_phy2_now = self.get_inteface_tx_packets_phy(self.bond_slaves[1])

        assert tx_packets_phy1_now - self.tx_packets_phy1_init >= self.tx_packets_phy1
        assert tx_packets_phy2_now - self.tx_packets_phy2_init >= self.tx_packets_phy2

    def update_tx_packets(self):
        port_num, active_port_num = Mlx5QP.query_lag_port(self.send_qp.qp)

        if active_port_num == 1 :
            self.tx_packets_phy1 += 1
        else :
            self.tx_packets_phy2 += 1

    def rc_traffic(self):
        Mlx5QP.modify_lag_port(self.send_qp.qp, 1)

        affinity_port_num, active_port_num = Mlx5QP.query_lag_port(self.send_qp.qp)
        assert affinity_port_num == 1

        while self.is_not_timeout():
            self.post_recv()

            send_val = 0xcafebeef
            self.post_send(send_val)

            self.poll_send()
            self.poll_recv()

            recv_val = int.from_bytes(self.recv_qp.mr.read(4, offset = 0), byteorder='little')
            assert recv_val == send_val

            self.update_tx_packets()

    def create_resources(self):
        self.send_qp = RCResources(dev_name = self.send_dev,
                                   print_fun = self.print_fun)
        self.recv_qp = RCResources(dev_name = self.recv_dev,
                                   print_fun = self.print_fun)

    def connect_qps(self):
        self.recv_qp.qp_init2rtr(self.send_qp)
        self.send_qp.qp_init2rtr(self.recv_qp)
        self.send_qp.qp_rtr2rts()

def main():
    parser = ArgsParser()
    parser.parse_args()

    RCTrafficTest(send_dev = parser.args['send_dev'], recv_dev = parser.args['recv_dev'], timeout = parser.args['timeout'])

if __name__ == "__main__":
    main()
