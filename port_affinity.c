/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2022 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#include <rdma/rdma_cma.h>
#include <infiniband/mlx5dv.h>

struct cm_context {
	struct rdma_event_channel* event_ch;
	struct rdma_cm_id *listen_id;
	struct rdma_cm_id *id;
	struct ibv_qp *dummy_qp;
	struct ibv_cq *dummy_cq;
	char dev_name[32];

	int is_server;
	char *server_addr;
	char *server_port;
};

#define MSG_SIZE 16384
#define MSG_CNT  3
struct memory_domain {
	struct ibv_device *dev;
	int    port_idx;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_qp *qp;


	struct ibv_mr *mr;
	void *addr;

	uint32_t local_qp_num;
	uint32_t remote_qp_num;

	struct ibv_qp_attr qp_attr;
	int qp_attr_mask;
};

void usage(const char *argv0)
{
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, " %s -s -a <server_bind_addr> start server\n", argv0);
	fprintf(stdout, " %s -a <server_listen_addr> start client\n", argv0);
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, " -p, --port <port> listen/connect port, default : %d\n");
}

int parse_command_line(int argc, char *argv[], struct cm_context *cm_ctx)
{
	memset(cm_ctx, 0, sizeof(*cm_ctx));

	cm_ctx->server_port = "51216";

	while (1) {
		int c;

		static struct option long_options[] = {
			{.name = "is_server",   .has_arg = 0, .val = 's'},
			{.name = "server_addr", .has_arg = 1, .val = 'a'},
			{.name = "port",        .has_arg = 1, .val = 'p'},
			{.name = NULL,          .has_arg = 0, .val = '\0'}
		};

		c = getopt_long(argc, argv, "sa:p:", long_options, NULL);
		if (c == -1) {
			break;
		}

		switch (c) {
		case 's':
			cm_ctx->is_server   = 1;
			break;
		case 'a':
			cm_ctx->server_addr = optarg;
			break;
		case 'p':
			cm_ctx->server_port = optarg;
			break;
		default:
			usage(argv[0]);
			return 1;
		}
	}

	if (optind != argc) {
		usage(argv[0]);
		return 1;
	}

	return 0;
}

int init_client_cm(struct cm_context *cm_ctx, struct rdma_addrinfo *rai)
{
	int ret_val = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = rdma_resolve_addr(cm_ctx->id, NULL, rai->ai_dst_addr, 1000);
	if (ret_val) {
		return ret_val;
	}

	ret_val = rdma_get_cm_event(cm_ctx->event_ch, &event);
	if (ret_val) {
		return ret_val;
	}

	if (event->event != RDMA_CM_EVENT_ADDR_RESOLVED) {
		rdma_ack_cm_event(event);
		return -1;
	}
	rdma_ack_cm_event(event);

	ret_val = rdma_resolve_route(cm_ctx->id, 1000);
	if (ret_val) {
		return ret_val;
	}

	ret_val = rdma_get_cm_event(cm_ctx->event_ch, &event);
	if (ret_val) {
		return ret_val;
	}

	if (event->event != RDMA_CM_EVENT_ROUTE_RESOLVED) {
		rdma_ack_cm_event(event);
		return -1;
	}
	rdma_ack_cm_event(event);

    snprintf(cm_ctx->dev_name, 32, "%s:%d",
             ibv_get_device_name(cm_ctx->id->verbs->device), cm_ctx->id->port_num);

	return 0;
}

int init_server_cm(struct cm_context *cm_ctx, struct rdma_addrinfo *rai)
{
	int ret_val = 0;

	ret_val = rdma_bind_addr(cm_ctx->listen_id, rai->ai_src_addr);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int init_qp_attr(struct cm_context *cm_ctx, struct memory_domain *md)
{
	int ret_val = 0;

	md->qp_attr.qp_state = IBV_QPS_RTR;
	ret_val = rdma_init_qp_attr(cm_ctx->id, &md->qp_attr, &md->qp_attr_mask);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int wait_conn_resp(struct cm_context *cm_ctx, struct memory_domain *md)
{
	int ret_val = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = rdma_get_cm_event(cm_ctx->event_ch, &event);
	if (ret_val) {
		return ret_val;
	}

	if (event->event != RDMA_CM_EVENT_CONNECT_RESPONSE) {
		rdma_ack_cm_event(event);
		ret_val = -1;
		return ret_val;
	}

	md->remote_qp_num = *(uint32_t *)(event->param.conn.private_data);
	rdma_ack_cm_event(event);

	return 0;
}

int wait_conn_req(struct cm_context *cm_ctx, struct memory_domain *md)
{
	int ret_val = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = rdma_get_cm_event(cm_ctx->event_ch, &event);
	if (ret_val) {
		return ret_val;
	}

	if (event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		rdma_reject(event->id, NULL, 0);
		ret_val = -1;
		return ret_val;
	}

	cm_ctx->id = event->id;
	snprintf(cm_ctx->dev_name, 32, "%s:%d",
             ibv_get_device_name(cm_ctx->id->verbs->device), cm_ctx->id->port_num);

	md->remote_qp_num = *(uint32_t *)(event->param.conn.private_data);
	rdma_ack_cm_event(event);
	return 0;
}

int wait_conn_establish(struct cm_context *cm_ctx)
{
	int ret_val = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = rdma_get_cm_event(cm_ctx->event_ch, &event);
	if (ret_val) {
		return ret_val;
	}

	if (event->event != RDMA_CM_EVENT_ESTABLISHED) {
		rdma_ack_cm_event(event);
		ret_val = -1;
		return ret_val;
	}

	return rdma_ack_cm_event(event);
}

int cm_client_establish(struct cm_context *cm_ctx)
{
	int ret_val = 0;

	ret_val = rdma_establish(cm_ctx->id);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int init_cm(struct cm_context *cm_ctx, struct rdma_addrinfo *rai)
{
	int ret_val = 0;
	struct rdma_event_channel *event_ch = NULL;
	struct rdma_cm_id *id = NULL;

	event_ch = rdma_create_event_channel();
	if (event_ch == NULL) {
		ret_val = -1;
		return ret_val;
	}

	ret_val = rdma_create_id(event_ch, &id, cm_ctx, RDMA_PS_TCP);
	if (ret_val) {
		rdma_destroy_event_channel(event_ch);
		return ret_val;
	}

	cm_ctx->event_ch = event_ch;
	/* It needs to bind the id to a particular RDMA device
     * This is done by resolving the address or binding to the address
	 */
	if (cm_ctx->is_server == 0) {
		cm_ctx->id = id;
        ret_val = init_client_cm(cm_ctx, rai);
	} else {
		cm_ctx->listen_id = id;
		ret_val = init_server_cm(cm_ctx, rai);
	}

	if (ret_val) {
		rdma_destroy_id(id);
		rdma_destroy_event_channel(event_ch);
		cm_ctx->event_ch = NULL;
		cm_ctx->id = NULL;
		cm_ctx->listen_id = NULL;
		return ret_val;
	}

	return 0;
}

struct ibv_device *get_ibv_device(struct ibv_device **devs, struct cm_context *cm_ctx)
{
	if (devs == NULL) {
		return NULL;
	}

	while (*devs) {
		if (strncmp((*devs)->name, cm_ctx->dev_name, strstr(cm_ctx->dev_name, ":") - cm_ctx->dev_name) == 0) {
			return *devs;
		}
		devs++;
	}

	return NULL;
}

struct ibv_qp *create_rc_qp(const struct memory_domain *md)
{
	struct ibv_qp *qp = NULL;
	struct ibv_qp_init_attr qp_init_attr = {};

	qp_init_attr.qp_context          = md->ctx;
	qp_init_attr.send_cq             = md->cq;
	qp_init_attr.recv_cq             = md->cq;
	qp_init_attr.cap.max_send_wr     = MSG_CNT;
	qp_init_attr.cap.max_recv_wr     = MSG_CNT;
	qp_init_attr.cap.max_send_sge    = 1;
	qp_init_attr.cap.max_recv_sge    = 1;
	qp_init_attr.qp_type             = IBV_QPT_RC;

	qp = ibv_create_qp(md->pd, &qp_init_attr);
	if (qp == NULL) {
		return NULL;
	}

	return qp;
}

int rc_qp_rst2init(struct ibv_qp *qp, int port_num)
{
	struct ibv_qp_attr qp_attr_init = {};
	qp_attr_init.qp_state        = IBV_QPS_INIT;
	qp_attr_init.qp_access_flags = IBV_ACCESS_LOCAL_WRITE;
	qp_attr_init.port_num        = port_num;

	if (ibv_modify_qp(qp, &qp_attr_init,
		IBV_QP_STATE | IBV_QP_PORT |
		IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS)) {
		return -1;
	}

	return 0;
}

int rc_qp_init2rtr(struct ibv_qp *qp,
				   const struct ibv_qp_attr qp_attr,
				   const int qp_attr_mask,
				   const int remote_qp_num)
{
	int ret_val = 0;

	struct ibv_qp_attr attr = qp_attr;
	int attr_mask           = qp_attr_mask;

	attr.dest_qp_num = remote_qp_num;
	attr.rq_psn      = 0;

	ret_val = ibv_modify_qp(qp, &attr, attr_mask);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int rc_qp_rtr2rst(struct ibv_qp *qp)
{
	int ret_val = 0;

	struct ibv_qp_attr attr = {};
	int attr_mask = IBV_QP_STATE | IBV_QP_TIMEOUT |
					IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
					IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

	attr.qp_state = IBV_QPS_RTS;
	attr.timeout = 0x12;
	attr.retry_cnt = 7;
	attr.rnr_retry = 7;
	attr.max_rd_atomic = 1;
	attr.sq_psn = 0;

	ret_val = ibv_modify_qp(qp, &attr, attr_mask);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int init_md(struct cm_context *cm_ctx, struct memory_domain *md)
{
	int ret_val = -1;

	struct ibv_device **dev_list = ibv_get_device_list(NULL);
	struct ibv_device *dev = get_ibv_device(dev_list, cm_ctx);

	if (dev == NULL) {
		goto free_dev_list;
	}

	md->port_idx = strtol(strstr(cm_ctx->dev_name, ":") + 1, NULL, 10);

	md->ctx = ibv_open_device(dev);
	if (md->ctx == NULL) {
		goto free_dev_list;
	}

	md->pd = ibv_alloc_pd(md->ctx);
	if (md->pd == NULL) {
		goto close_ctx;
	}

	md->cq = ibv_create_cq(md->ctx, 2 * MSG_CNT, NULL, NULL, 0);
	if (md->cq == NULL) {
		goto free_pd;
	}

	md->addr = malloc(MSG_SIZE * MSG_CNT);
	if (md->addr == NULL) {
		goto free_cq;
	}

	md->mr = ibv_reg_mr(md->pd, md->addr, MSG_SIZE * MSG_CNT, IB_UVERBS_ACCESS_LOCAL_WRITE | IB_UVERBS_ACCESS_REMOTE_READ);
	if (md->mr == NULL) {
		goto free_addr;
	}

	ret_val = 0;
	goto free_dev_list;

free_addr:
	free(md->addr);
	md->addr = NULL;

free_cq:
	ibv_destroy_cq(md->cq);
	md->cq = NULL;

free_pd:
	ibv_dealloc_pd(md->pd);
	md->pd = NULL;

close_ctx:
	ibv_close_device(md->ctx);
	md->ctx = NULL;

free_dev_list:
	ibv_free_device_list(dev_list);

	return ret_val;
}

int cm_dummy_ud_qp(struct cm_context *cm_ctx)
{
	int ret_val = 0;
	struct ibv_qp_init_attr qp_init_attr = {};
	struct ibv_qp *qp;


	cm_ctx->dummy_cq = ibv_create_cq(cm_ctx->id->verbs, 1, NULL, NULL, 0);
	if (cm_ctx->dummy_cq == NULL) {
		return -1;
	}

	/* Create a dummy UD qp */
	qp_init_attr.send_cq          = cm_ctx->dummy_cq;
	qp_init_attr.recv_cq          = cm_ctx->dummy_cq;
	qp_init_attr.qp_type          = IBV_QPT_UD;
	qp_init_attr.cap.max_send_wr  = 2;
	qp_init_attr.cap.max_recv_wr  = 2;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;

	cm_ctx->dummy_qp = ibv_create_qp(cm_ctx->id->pd, &qp_init_attr);
    if (cm_ctx->dummy_qp == NULL) {
		ibv_destroy_cq(cm_ctx->dummy_cq);
		cm_ctx->dummy_cq = NULL;
		return -1;
    }

	return 0;
}

int cm_client_connect(struct cm_context *cm_ctx, struct memory_domain *md)
{
	int ret_val = 0;
	struct rdma_conn_param conn_param = {};

	conn_param.private_data_len = sizeof(md->local_qp_num);
	conn_param.private_data     = &md->local_qp_num;
	conn_param.qp_num           = cm_ctx->dummy_qp->qp_num;

	conn_param.responder_resources = 2;
	conn_param.initiator_depth     = 2;
	conn_param.retry_count         = 5;
	conn_param.rnr_retry_count     = 5;

	ret_val = rdma_connect(cm_ctx->id, &conn_param);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int client_post_recv(struct memory_domain *md)
{
	int ret_val = 0;

	struct ibv_sge sge0, sge1, sge2;
	struct ibv_recv_wr wr0, wr1, wr2;
	struct ibv_recv_wr *bad_rwr;

	sge0.addr   = (uint64_t)md->mr->addr;
	sge0.length = MSG_SIZE;
	sge0.lkey   = md->mr->lkey;

	sge1.addr   = sge0.addr + sge0.length;
	sge1.length = sge0.length;
	sge1.lkey   = md->mr->lkey;

	sge2.addr   = sge1.addr + sge1.length;
	sge2.length = sge1.length;
	sge2.lkey   = md->mr->lkey;

	wr2.wr_id   = 2;
	wr2.next    = NULL;
	wr2.sg_list = &sge2;
	wr2.num_sge = 1;

	wr1.wr_id   = 1;
	wr1.next    = &wr2;
	wr1.sg_list = &sge1;
	wr1.num_sge = 1;

	wr0.wr_id   = 0;
	wr0.next    = &wr1;
	wr0.sg_list = &sge0;
	wr0.num_sge = 1;

	ret_val = ibv_post_recv(md->qp, &wr0, &bad_rwr);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int server_post_send(struct memory_domain *md, uint64_t wr_id)
{
	int ret_val = 0;

	struct ibv_sge sge;
	struct ibv_send_wr wr = {0};
	struct ibv_send_wr *bad_swr;

	sge.addr = (uint64_t)md->mr->addr;
	sge.length = MSG_SIZE;
	sge.lkey = md->mr->lkey;

	wr.wr_id = wr_id;
	wr.next  = NULL;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.opcode = IBV_WR_SEND;
	wr.send_flags = IBV_SEND_SIGNALED;

	ret_val = ibv_post_send(md->qp, &wr, &bad_swr);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int run_client(struct cm_context *cm_ctx, struct memory_domain *md)
{
	int ret_val = 0;

	ret_val = init_md(cm_ctx, md);
	if (ret_val) {
		return ret_val;
	}

	md->qp = create_rc_qp(md);
	if (md->qp == NULL) {
		ret_val = -1;
		goto free_md;
	}

	ret_val = rc_qp_rst2init(md->qp, md->port_idx);
	if (ret_val) {
		goto free_qp;
	}

	md->local_qp_num = md->qp->qp_num;

	ret_val = cm_dummy_ud_qp(cm_ctx);
	if (ret_val) {
		goto free_qp;
	}

	ret_val = cm_client_connect(cm_ctx, md);
	if (ret_val) {
		goto free_dummy_qp;
	}

	ret_val = wait_conn_resp(cm_ctx, md);
	if (ret_val) {
		goto free_dummy_qp;
	}

	ret_val = init_qp_attr(cm_ctx, md);
	if (ret_val) {
		goto free_dummy_qp;
	}

	ret_val = rc_qp_init2rtr(md->qp, md->qp_attr, md->qp_attr_mask, md->remote_qp_num);
	if (ret_val) {
		goto free_dummy_qp;
	}

	ret_val = client_post_recv(md);
	if (ret_val) {
		goto free_dummy_qp;
	}

	ret_val = cm_client_establish(cm_ctx);
	if (ret_val) {
		return ret_val;
	}

	return ret_val;

free_dummy_qp:
	ibv_destroy_qp(cm_ctx->dummy_qp);
	cm_ctx->dummy_qp = NULL;

	ibv_destroy_cq(cm_ctx->dummy_cq);
	cm_ctx->dummy_cq = NULL;

free_qp:
	ibv_destroy_qp(md->qp);
	md->qp = NULL;

free_md:
	free(md->addr);
	md->addr = NULL;

	ibv_destroy_cq(md->cq);
	md->cq = NULL;

	ibv_dealloc_pd(md->pd);
	md->pd = NULL;

	ibv_close_device(md->ctx);
	md->ctx = NULL;
		
	return ret_val;
}

int listen_connection(struct cm_context *cm_ctx)
{
	int ret_val = 0;

	ret_val = rdma_listen(cm_ctx->listen_id, 1);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int cm_server_accept(struct cm_context *cm_ctx, struct memory_domain *md)
{
	int ret_val = 0;
	struct rdma_conn_param conn_param = {};

	conn_param.private_data_len = sizeof(md->local_qp_num);
	conn_param.private_data     = &md->local_qp_num;
	conn_param.qp_num           = cm_ctx->dummy_qp->qp_num;

	ret_val = rdma_accept(cm_ctx->id, &conn_param);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int run_server(struct cm_context *cm_ctx, struct memory_domain *md)
{
	int ret_val = 0;

	ret_val = listen_connection(cm_ctx);
	if (ret_val) {
		return ret_val;
	}

	ret_val = wait_conn_req(cm_ctx, md);
	if (ret_val) {
		return ret_val;
	}

	ret_val = init_qp_attr(cm_ctx, md);
	if (ret_val) {
		return ret_val;
	}

	ret_val = init_md(cm_ctx, md);
	if (ret_val) {
		return ret_val;
	}

	md->qp = create_rc_qp(md);
	if (md->qp == NULL) {
		ret_val = -1;
		goto err_qp;
	}
	md->local_qp_num = md->qp->qp_num;

	ret_val = rc_qp_rst2init(md->qp, md->port_idx);
	if (ret_val) {
		goto free_qp;
	}

	ret_val = rc_qp_init2rtr(md->qp, md->qp_attr, md->qp_attr_mask, md->remote_qp_num);
	if (ret_val) {
		goto free_qp;
	}

	ret_val = rc_qp_rtr2rst(md->qp);
	if (ret_val) {
		goto free_qp;
	}

	ret_val = cm_dummy_ud_qp(cm_ctx);
	if (ret_val) {
		goto free_qp;
	}

	ret_val = cm_server_accept(cm_ctx, md);
	if (ret_val) {
		return ret_val;
	}

	ret_val = wait_conn_establish(cm_ctx);
	if (ret_val) {
		return ret_val;
	}

	ret_val = server_post_send(md, 0);
	if (ret_val) {
		return ret_val;
	}

	return ret_val;

free_qp:
	ibv_destroy_qp(md->qp);
	md->qp = NULL;

err_qp:
	if (md->mr) {
		ibv_dereg_mr(md->mr);
		md->mr = NULL;
	}

	if (md->addr) {
		free(md->addr);
		md->addr = NULL;
	}

	if (md->cq) {
		ibv_destroy_cq(md->cq);
		md->cq = NULL;
	}

	if (md->pd) {
		ibv_dealloc_pd(md->pd);
		md->pd = NULL;
	}

	if (md->ctx) {
		ibv_close_device(md->ctx);
		md->ctx = NULL;
	}

	return ret_val;
}

int main(int argc, char *argv[])
{
	struct cm_context cm_ctx = {};
	struct memory_domain md = {};
	struct rdma_addrinfo *rai, hints = {};
	int ret_val = 0;

	ret_val = parse_command_line(argc, argv, &cm_ctx);
	if (ret_val || cm_ctx.server_addr == NULL) {
		return ret_val;
	}

	hints.ai_port_space = RDMA_PS_TCP;
	if (cm_ctx.is_server == 1) {
		/* This makes it a server */
		hints.ai_flags = RAI_PASSIVE;
	}

	ret_val = rdma_getaddrinfo(cm_ctx.server_addr, cm_ctx.server_port, &hints, &rai);
	if (ret_val) {
		return ret_val;
	}

	ret_val = init_cm(&cm_ctx, rai);
	rdma_freeaddrinfo(rai);
	if (ret_val) {
		return ret_val;
	}

	if (cm_ctx.is_server) {
		ret_val = run_server(&cm_ctx, &md);
	} else {
		ret_val = run_client(&cm_ctx, &md);
	}

	return ret_val;
}
