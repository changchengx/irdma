/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2023 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include <rdma/rdma_cma.h>

struct cm_context {
	struct rdma_event_channel* event_ch;
	struct rdma_cm_id *listen_id;
	struct rdma_cm_id **id;
	struct ibv_qp *dummy_qp;
	struct ibv_cq *dummy_cq;

	int conns;
	int is_server;
	char *server_addr;
	char *server_port;
};

void usage(const char *argv0)
{
	fprintf(stdout, "Usage:\n");
	fprintf(stdout, " %s -s -a <server_bind_addr> start server\n", argv0);
	fprintf(stdout, " %s -a <server_listen_addr> start client\n", argv0);
	fprintf(stdout, "\n");
	fprintf(stdout, "Options:\n");
	fprintf(stdout, " -p, --port <port> listen/connect port, default : 51216\n");
	fprintf(stdout, " -c, --conn <number> connect number times, default : 1\n");
}

int parse_command_line(int argc, char *argv[], struct cm_context *cm_ctx)
{
	memset(cm_ctx, 0, sizeof(*cm_ctx));

	cm_ctx->server_port = "51216";
	cm_ctx->conns       = 1;

	while (1) {
		int c;

		static struct option long_options[] = {
			{.name = "is_server",   .has_arg = 0, .val = 's'},
			{.name = "server_addr", .has_arg = 1, .val = 'a'},
			{.name = "port",        .has_arg = 1, .val = 'p'},
			{.name = "conn",        .has_arg = 1, .val = 'c'},
			{.name = NULL,          .has_arg = 0, .val = '\0'}
		};

		c = getopt_long(argc, argv, "sa:c:p:", long_options, NULL);
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
		case 'c':
			cm_ctx->conns = atoi(optarg);
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

	cm_ctx->id = calloc(cm_ctx->conns, sizeof(cm_ctx->id[0]));
	if (cm_ctx->id == NULL) {
		return 1;
	}

	printf("is_server:%d, server_addr:%s, port:%s, try establish %d connections\n",
	        cm_ctx->is_server, cm_ctx->server_addr, cm_ctx->server_port, cm_ctx->conns);

	return 0;
}

void report_unexpected_event(enum rdma_cm_event_type expected_event,
                             struct rdma_cm_event *unexpected_event)
{
	printf("expected event: %s, got: %s\n",
	        rdma_event_str(expected_event),
	        rdma_event_str(unexpected_event->event));
}

int wait_expected_event(struct cm_context *cm_ctx, int conn_idx,
                        struct rdma_cm_event **eventh,
                        enum rdma_cm_event_type expected_event)
{
	int ret_val = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = rdma_get_cm_event(cm_ctx->event_ch, &event);
	if (ret_val) {
		printf("%m\n");
		return ret_val;
	}

	if (expected_event != event->event) {
		report_unexpected_event(expected_event, event);
		rdma_ack_cm_event(event);
		return -1;
	}

	*eventh = event;
	return 0;
}

int init_client_cm(struct cm_context *cm_ctx, struct rdma_addrinfo *rai, int conn_idx)
{
	int ret_val = 0;
	struct rdma_cm_id *id = NULL;
	struct rdma_cm_event *event = NULL;

	ret_val = rdma_create_id(cm_ctx->event_ch, &id, cm_ctx, RDMA_PS_TCP);
	if (ret_val) {
		return ret_val;
	}
	cm_ctx->id[conn_idx] = id;

	ret_val = rdma_resolve_addr(cm_ctx->id[conn_idx], NULL, rai->ai_dst_addr, 1000);
	if (ret_val) {
		printf("%m\n");
		return ret_val;
	}

	ret_val = wait_expected_event(cm_ctx, conn_idx, &event, RDMA_CM_EVENT_ADDR_RESOLVED);
	if (ret_val) {
		return ret_val;
	}
	rdma_ack_cm_event(event);

	ret_val = rdma_resolve_route(cm_ctx->id[conn_idx], 1000);
	if (ret_val) {
		return ret_val;
	}

	ret_val = wait_expected_event(cm_ctx, conn_idx, &event, RDMA_CM_EVENT_ROUTE_RESOLVED);
	if (ret_val) {
		return ret_val;
	}
	rdma_ack_cm_event(event);

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

int wait_conn_resp(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;
	int resp_data = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = wait_expected_event(cm_ctx, conn_idx, &event, RDMA_CM_EVENT_CONNECT_RESPONSE);
	if (ret_val) {
		return ret_val;
	}

	resp_data = *(int32_t *)(event->param.conn.private_data);
	if (resp_data != conn_idx + 100) {
		printf("client got wrong data\n");
	}
	rdma_ack_cm_event(event);

	return 0;
}

int wait_conn_req(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;
	int resp_data = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = rdma_get_cm_event(cm_ctx->event_ch, &event);
	if (ret_val) {
		printf("%m\n");
		return ret_val;
	}

	if (RDMA_CM_EVENT_CONNECT_REQUEST != event->event) {
		report_unexpected_event(RDMA_CM_EVENT_CONNECT_REQUEST, event);
		rdma_reject(event->id, NULL, 0);
		rdma_ack_cm_event(event);
		return -1;
	}
	cm_ctx->id[conn_idx] = event->id;

	resp_data = *(int32_t *)(event->param.conn.private_data);
	if (resp_data != conn_idx + 100) {
		printf("client got wrong data\n");
	}
	rdma_ack_cm_event(event);
	return 0;
}

int wait_conn_establish(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = wait_expected_event(cm_ctx, conn_idx, &event, RDMA_CM_EVENT_ESTABLISHED);
	if (ret_val) {
		return ret_val;
	}

	return rdma_ack_cm_event(event);
}

int cm_client_establish(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;

	ret_val = rdma_establish(cm_ctx->id[conn_idx]);
	if (ret_val) {
		printf("client established failed\n");
		return ret_val;
	}

	return 0;
}

int wait_conn_disconnected(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = wait_expected_event(cm_ctx, conn_idx, &event, RDMA_CM_EVENT_DISCONNECTED);
	if (ret_val) {
		return ret_val;
	}

	return rdma_ack_cm_event(event);
}

int wait_timewait_exited(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;
	struct rdma_cm_event *event = NULL;

	ret_val = wait_expected_event(cm_ctx, conn_idx, &event, RDMA_CM_EVENT_TIMEWAIT_EXIT);
	if (ret_val) {
		return ret_val;
	}

	return rdma_ack_cm_event(event);
}

int cm_disconnect(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;

	ret_val = rdma_disconnect(cm_ctx->id[conn_idx]);
	if (ret_val) {
		printf("client disconnect failed\n");
		return ret_val;
	}

	return 0;
}

int init_event_channel(struct cm_context *cm_ctx)
{
	int ret_val = 0;
	struct rdma_event_channel *event_ch = NULL;

	event_ch = rdma_create_event_channel();
	if (event_ch == NULL) {
		ret_val = -1;
		return ret_val;
	}

	cm_ctx->event_ch = event_ch;

	return 0;
}
int init_listen_id(struct cm_context *cm_ctx, struct rdma_addrinfo *rai)
{
	int ret_val = 0;
	struct rdma_cm_id *id = NULL;

	ret_val = rdma_create_id(cm_ctx->event_ch, &id, cm_ctx, RDMA_PS_TCP);
	if (ret_val) {
		return ret_val;
	}

	cm_ctx->listen_id = id;
	ret_val = rdma_bind_addr(cm_ctx->listen_id, rai->ai_src_addr);

	if (ret_val) {
		rdma_destroy_id(id);
		cm_ctx->id = NULL;
		cm_ctx->listen_id = NULL;
		return ret_val;
	}

	return 0;
}

int cm_dummy_ud_qp(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;
	struct ibv_qp_init_attr qp_init_attr = {};

#if defined(SAME_QP)
	if (cm_ctx->dummy_qp != NULL) {
		return 0;
	}
#endif

	cm_ctx->dummy_cq = ibv_create_cq(cm_ctx->id[conn_idx]->verbs, 1, NULL, NULL, 0);
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

	cm_ctx->dummy_qp = ibv_create_qp(cm_ctx->id[conn_idx]->pd, &qp_init_attr);
	if (cm_ctx->dummy_qp == NULL) {
		ibv_destroy_cq(cm_ctx->dummy_cq);
		cm_ctx->dummy_cq = NULL;
		return -1;
	}

	return 0;
}

int cm_client_connect(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;
	int priv_val = conn_idx + 100;
	struct rdma_conn_param conn_param = {};

	conn_param.private_data_len = sizeof(priv_val);
	conn_param.private_data     = &priv_val;
	conn_param.qp_num           = cm_ctx->dummy_qp->qp_num;

	conn_param.responder_resources = 2;
	conn_param.initiator_depth     = 2;
	conn_param.retry_count         = 5;
	conn_param.rnr_retry_count     = 5;

	ret_val = rdma_connect(cm_ctx->id[conn_idx], &conn_param);
	if (ret_val) {
		printf("client connect failed\n");
		return ret_val;
	}

	return 0;
}

int run_client(struct cm_context *cm_ctx, struct rdma_addrinfo *rai)
{
	int ret_val = 0;
	int conn_idx = 0;

	for (conn_idx = 0; conn_idx < cm_ctx->conns; conn_idx++) {
		ret_val = init_client_cm(cm_ctx, rai, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = cm_dummy_ud_qp(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = cm_client_connect(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = wait_conn_resp(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = cm_client_establish(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

#if !defined(SAME_QP)
		ret_val = cm_disconnect(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = wait_conn_disconnected(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = wait_timewait_exited(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}
#endif

		if (conn_idx != cm_ctx->conns - 1) {
			sleep(4);
		}
	}

	printf("%d: conn_idx = %d\n", __LINE__, conn_idx);

	return ret_val;
}

int listen_connection(struct cm_context *cm_ctx)
{
	int ret_val = 0;

	ret_val = rdma_listen(cm_ctx->listen_id, 64);
	if (ret_val) {
		return ret_val;
	}

	return 0;
}

int cm_server_accept(struct cm_context *cm_ctx, int conn_idx)
{
	int ret_val = 0;
	int priv_val = conn_idx + 100;
	struct rdma_conn_param conn_param = {};

	conn_param.private_data_len = sizeof(priv_val);
	conn_param.private_data     = &priv_val;
	conn_param.qp_num           = cm_ctx->dummy_qp->qp_num;

	ret_val = rdma_accept(cm_ctx->id[conn_idx], &conn_param);
	if (ret_val) {
		printf("server accept failed\n");
		return ret_val;
	}

	return 0;
}

int run_server(struct cm_context *cm_ctx, struct rdma_addrinfo *rai)
{
	int ret_val = 0;
	int conn_idx = 0;

	ret_val = init_listen_id(cm_ctx, rai);
	if (ret_val) {
		rdma_destroy_event_channel(cm_ctx->event_ch);
		cm_ctx->event_ch = NULL;
	}

	ret_val = listen_connection(cm_ctx);
	if (ret_val) {
		rdma_destroy_event_channel(cm_ctx->event_ch);
		cm_ctx->event_ch = NULL;
		return ret_val;
	}

	for (conn_idx = 0; conn_idx < cm_ctx->conns; conn_idx++) {
		ret_val = wait_conn_req(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = cm_dummy_ud_qp(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = cm_server_accept(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = wait_conn_establish(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

#if !defined(SAME_QP)
		ret_val = wait_conn_disconnected(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = cm_disconnect(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}

		ret_val = wait_timewait_exited(cm_ctx, conn_idx);
		if (ret_val) {
			printf("%d: conn_idx = %d\n", __LINE__, conn_idx);
			return ret_val;
		}
#endif
	}

	printf("%d: conn_idx = %d\n", __LINE__, conn_idx);

	return ret_val;
}

int main(int argc, char *argv[])
{
	struct cm_context cm_ctx = {};
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

	ret_val = init_event_channel(&cm_ctx);
	if (ret_val) {
		return ret_val;
	}


	if (cm_ctx.is_server) {
		ret_val = run_server(&cm_ctx, rai);
	} else {
		ret_val = run_client(&cm_ctx, rai);
	}

	return ret_val;
}
