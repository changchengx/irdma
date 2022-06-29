#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Liu, Changcheng <changcheng.liu@aliyun.com>

import sys
import time
import argparse

from pyverbs.cq import CQ
from pyverbs.mr import MR
from pyverbs.providers.mlx5.mlx5dv import Mlx5QP
from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
from pyverbs.cmid import CMID, AddrInfo, CMEventChannel, CMEvent, ConnParam
from pyverbs.wr import SGE, SendWR, RecvWR
import pyverbs.cm_enums as ce
import pyverbs.enums as e

class ArgsParser(object):
    def __init__(self):
        self.args = None

    def get_config(self):
        return self.args

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
        self.dev_name  = None

        self.dummy_qp  = None
        self.dummy_cq  = None

        self.is_server   = False
        self.server_addr = None
        self.server_port = "51216"
        self.ai          = None

        self.md          = memory_domain()

    def dummy_ud_qp(self):
        self.dummy_cq = CQ(self.id.context, 1, None, None, 0)
        qp_cap = QPCap(max_send_wr = 2, max_recv_wr = 2,
                       max_send_sge = 1, max_recv_sge = 1)
        qp_init_attr = QPInitAttr(qp_type = e.IBV_QPT_UD,
                                  scq = self.dummy_cq,
                                  rcq = self.dummy_cq,
                                  cap = qp_cap, sq_sig_all = 0)
        self.dummy_qp = QP(self.id.pd, qp_init_attr)

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
        self.md.cq = CQ(self.id.context, 3, None, None, 0)
        self.md.mr = MR(self.id.pd, 16384 * 3, e.IBV_ACCESS_LOCAL_WRITE)

    def qp_rst2init(self):
        qp_attr = QPAttr()
        qp_attr.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE
        qp_attr.port_num = 1
        self.md.qp.to_init(qp_attr)

    def qp_init2rtr(self):
        qp_attr = self.md.qp_attr
        qp_attr.dest_qp_num = self.md.remote_qp_num
        qp_attr.rq_psn = 0
        self.md.qp.to_rtr(qp_attr)

    def qp_rtr2rts(self):
        qp_attr, _ = self.md.qp.query(e.IBV_QP_STATE)

        qp_attr.qp_state = e.IBV_QPS_RTS
        qp_attr.max_rd_atomic = 1;
        qp_attr.timeout = 0x12;
        qp_attr.retry_cnt = 7;
        qp_attr.rnr_retry = 7;
        qp_attr.sq_psn = 0;

        self.md.qp.to_rts(qp_attr)

    def create_rc_qp(self):
        qp_cap = QPCap(max_send_wr = 3, max_recv_wr = 3,
                       max_send_sge = 1, max_recv_sge = 1)
        qp_init_attr = QPInitAttr(qp_type = e.IBV_QPT_RC,
                                  scq = self.md.cq,
                                  rcq = self.md.cq,
                                  cap = qp_cap)
        self.md.qp = QP(self.id.pd, qp_init_attr)

    def init_qp_attr(self):
        self.md.qp_attr, self.md.qp_attr_mask = self.id.init_qp_attr(e.IBV_QPS_RTR)

    def client_connect(self):
        conn_param = ConnParam(resources = 2, depth = 2, retry = 5, rnr_retry = 5, qp_num = self.dummy_qp.qp_num, data_len = 56)
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

    def client_disconnect(self):
        self.id.disconnect()

    def wait_discon_event(self):
        cm_event = CMEvent(self.event_ch)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_DISCONNECTED

    def client_post_recv(self):
        sge0 = SGE(self.md.mr.buf, 16384, self.md.mr.lkey)
        sge1 = SGE(sge0.addr + sge0.length, sge0.length, self.md.mr.lkey)
        sge2 = SGE(sge1.addr + sge1.length, sge1.length, self.md.mr.lkey)

        rwr2 = RecvWR(wr_id = 2, num_sge = 1, sg = [sge2])
        rwr1 = RecvWR(wr_id = 1, num_sge = 1, sg = [sge1], next_wr = rwr2)
        rwr0 = RecvWR(wr_id = 0, num_sge = 1, sg = [sge0], next_wr = rwr1)

        self.md.qp.post_recv(rwr0)

    def run_client(self):
        self.init_md()

        self.create_rc_qp()

        self.md.local_qp_num = self.md.qp.qp_num

        self.dummy_ud_qp()

        self.client_connect()

        while self.wait_conn_resp() != 0:
            self.dummy_qp.close()
            self.dummy_cq.close()
            self.md.qp.close()
            self.md.cq.close()
            self.md.mr.close()
            self.id.close()

            self.create_cmid()
            self.init_client_cm()

            time.sleep(2)

            self.init_md()

            self.create_rc_qp()

            self.md.local_qp_num = self.md.qp.qp_num

            self.dummy_ud_qp()

            self.client_connect()

        self.init_qp_attr()

        self.qp_rst2init()

        self.qp_init2rtr()

        self.client_post_recv()

        self.client_establish()

        wcs_num = 0
        while wcs_num < 3:
            wc_num = 0
            wcs = []
            while wc_num == 0:
                wc_num, wcs = self.md.cq.poll(num_entries = 1)

            wcs_num = wcs_num + wc_num

            for idx in range(wc_num):
                wc = wcs[idx]
                assert wc.status == e.IBV_WC_SUCCESS
                wr_id = wc.wr_id
                val = int.from_bytes(self.md.mr.read(4, 16384 * wr_id), byteorder='little')
                assert val == 0xcafebeef + wr_id

        self.client_disconnect()
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
        conn_param = ConnParam(resources = 2, depth = 2, retry = 5, rnr_retry = 5, qp_num = self.dummy_qp.qp_num, data_len = 56)
        private_data = self.md.local_qp_num.to_bytes(4, byteorder='little')
        conn_param.set_private_data(private_data)
        self.id.accept(conn_param)

    def wait_conn_establish(self):
        cm_event = CMEvent(self.event_ch)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_ESTABLISHED

        cm_event.ack_cm_event()

    def server_post_send(self, wrid):
        val = int(0xcafebeef + wrid).to_bytes(4, byteorder = 'little')
        self.md.mr.write(val, length = 4, offset = 0)

        sge = SGE(self.md.mr.buf, 16384, self.md.mr.lkey)
        swr = SendWR(wr_id = wrid, opcode = e.IBV_WR_SEND, num_sge = 1, sg = [sge], send_flags=e.IBV_SEND_SIGNALED)

        self.md.qp.post_send(swr)

    def run_server(self):
        self.listen_connect()

        self.wait_conn_req()

        self.init_qp_attr()

        self.init_md()

        self.create_rc_qp()
        self.qp_rst2init()
        self.md.local_qp_num = self.md.qp.qp_num
        self.qp_init2rtr()
        self.qp_rtr2rts()

        self.dummy_ud_qp()

        self.accept_conn()

        self.wait_conn_establish()

        Mlx5QP.modify_lag_port(self.md.qp, 1)
        self.server_post_send(0)
        wc_num = 0
        while wc_num != 1:
            wc_num, _ = self.md.cq.poll(num_entries = 1)

        self.server_post_send(1)
        wc_num = 0
        while wc_num != 1:
            wc_num, _ = self.md.cq.poll(num_entries = 1)

        self.server_post_send(2)
        wc_num = 0
        while wc_num != 1:
            wc_num, _ = self.md.cq.poll(num_entries = 1)

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

    if cm_ctx.is_server == True:
        cm_ctx.run_server()
    else:
        cm_ctx.run_client()


if __name__ == "__main__":
    main()
