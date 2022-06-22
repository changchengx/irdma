#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2022 Liu, Changcheng <changcheng.liu@aliyun.com>

import sys
import argparse

from pyverbs.cq import CQ
from pyverbs.mr import MR
from pyverbs.qp import QPCap, QPInitAttr, QPAttr, QP
from pyverbs.cmid import CMID, AddrInfo, CMEventChannel, CMEvent, ConnParam
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
        self.addr = None

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
                                  cap = qp_cap)
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
        if self.is_server == True:
            self.md.cq = CQ(self.listen_id.context, 3, None, None, 0)
            self.md.mr = MR(self.listen_id.pd, 16384 * 3, e.IBV_ACCESS_LOCAL_WRITE)
        else:
            self.md.cq = CQ(self.id.context, 3, None, None, 0)
            self.md.mr = MR(self.id.pd, 16384 * 3, e.IBV_ACCESS_LOCAL_WRITE)

    def qp_rst2init(self):
        qp_attr = QPAttr()
        qp_attr.qp_access_flags = e.IBV_ACCESS_LOCAL_WRITE
        qp_attr.port_num = 1
        self.md.qp.to_init(qp_attr)

    def create_rc_qp(self):
        qp_cap = QPCap(max_send_wr = 3, max_recv_wr = 3,
                       max_send_sge = 1, max_recv_sge = 1)
        qp_init_attr = QPInitAttr(qp_type = e.IBV_QPT_RC,
                                  scq = self.md.cq,
                                  rcq = self.md.cq,
                                  cap = qp_cap)
        self.md.qp = QP(self.id.pd, qp_init_attr)

    def client_connect(self):
        conn_param = ConnParam(resources = 2, depth = 2, retry = 5, rnr_retry = 5, qp_num = self.dummy_qp.qp_num, data_len = 56)
        private_data = self.md.local_qp_num.to_bytes(4, byteorder='little')
        conn_param.set_private_data(private_data)
        self.id.connect(conn_param)

    def run_client(self):
        self.init_md()

        self.create_rc_qp()
        self.qp_rst2init()

        self.md.local_qp_num = self.md.qp.qp_num

        self.dummy_ud_qp()

        self.client_connect()

    def listen_connect(self):
        self.listen_id.listen(backlog = 1)

    def wait_conn_req(self):
        cm_event = CMEvent(self.event_ch)
        self.id = CMID(creator = cm_event, listen_id = self.listen_id)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_CONNECT_REQUEST

        private_data = cm_event.private_data
        self.md.remote_qp_num = int.from_bytes(private_data[:3], 'little')

        cm_event.ack_cm_event()

    def run_server(self):
        self.listen_connect()

        self.wait_conn_req()

def main():
    parser = ArgsParser()
    parser.parse_args()

    cm_ctx = cm_context()
    md     = memory_domain()

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
