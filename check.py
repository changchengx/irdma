#!/usr/bin/env python3

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


class cm_context:
    def __init__(self):
        self.event_ch  = CMEventChannel()
        self.listen_id = None
        self.id        = None
        self.dev_name  = None

        self.is_server   = False
        self.server_addr = None
        self.server_port = "51216"
        self.ai          = None

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

    def init_qp_attr(self):
        self.id.init_qp_attr(e.IBV_QPS_RTR)

    def client_connect(self):
        conn_param = ConnParam(resources = 2, depth = 2, retry = 5, rnr_retry = 5)
        self.id.connect(conn_param)

    def run_client(self):
        self.client_connect()

    def listen_connect(self):
        self.listen_id.listen(backlog = 1)

    def wait_conn_req(self):
        cm_event = CMEvent(self.event_ch)
        self.id = CMID(creator = cm_event, listen_id = self.listen_id)
        assert cm_event.event_type == ce.RDMA_CM_EVENT_CONNECT_REQUEST

        cm_event.ack_cm_event()

    def run_server(self):
        self.listen_connect()

        self.wait_conn_req()

        self.init_qp_attr()

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
