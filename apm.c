#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <rdma/rdma_verbs.h>

#define VERB_ERR(verb, ret) \
	fprintf(stderr, "%s returned %d errno %d\n", verb, ret, errno)

/* Default parameter values */
#define DEFAULT_PORT "51216"
#define DEFAULT_MSG_COUNT 100
#define DEFAULT_MSG_LENGTH 1000000
#define DEFAULT_MSEC_DELAY 500

struct context {
	int server;
	char *server_name;
	char *server_port;
	int msg_count;
	int msg_length;
	int msec_delay;
	uint8_t alt_srcport;
	uint16_t alt_dlid;
	uint16_t my_alt_dlid;
	int migrate_after;

	struct rdma_cm_id *id;
	struct rdma_cm_id *listen_id;
	struct ibv_mr *send_mr;
	struct ibv_mr *recv_mr;
	char *send_buf;
	char *recv_buf;
	pthread_t async_event_thread;
};

/* Function: async_event_thread
 *
 * Input:
 *  arg  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 * NULL
 *
 * Description:
 *  Reads any Asynchronous events that occur during the sending of data
 *  and prints out the details of the event. Specifically migration
 *  related events.
 */
static void *async_event_thread(void *arg)
{
	struct ibv_async_event event;
	int ret;

	struct context *ctx = (struct context *)arg;

	while (1) {
		ret = ibv_get_async_event(ctx->id->verbs, &event);
		if (ret) {
			VERB_ERR("ibv_get_async_event", ret);
			break;
		}

		switch (event.event_type) {
		case IBV_EVENT_PATH_MIG:
			printf("QP path migrated\n");
			break;
		case IBV_EVENT_PATH_MIG_ERR:
			printf("QP path migration error\n");
			break;
		default:
			printf("Async Event %d\n", event.event_type);
			break;
		}

		ibv_ack_async_event(&event);
	}

	return NULL;
}

/* Function: get_alt_dlid_from_private_data
 *
 * Input:
 *  event  The RDMA event containing private data
 *
 * Output:
 *  dlid  The DLID that was sent in the private dataz
 *
 * Returns:
 *  0  on success, non-zero on failure
 *
 * Description:
 *  Takes the private data sent from the remote side and returns the
 *  destination LID that was contained in the private data
 */
int get_alt_dlid_from_private_data(struct rdma_cm_event *event, uint16_t *dlid)
{
	if (event->param.conn.private_data_len < 4) {
		printf("unexpected private data len : %d", event->param.conn.private_data_len);
		return -1;
	}

	*dlid = ntohs(*((uint16_t*)event->param.conn.private_data));
	return 0;
}

/* Function: get_alt_port_details
 *
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 *
 * Description:
 *  First, query the device to determine if path migration is supported.
 *  Next, queries all the ports on the device to determine if there is
 *  different port than the current one to use as an alternate port. If so,
 *  copy the port number and dlid to the context so they can be used when
 *  the alternate path is loaded.
 *
 * Note:
 *  This function assumes that if another port is found in the active state,
 *  that the port is connected to the same subnet as the initial port and
 *  that there is route to the other hosts alternate port.
 */
int get_alt_port_details(struct context *ctx)
{
	int ret, i;
	struct ibv_qp_attr qp_attr;
	struct ibv_qp_init_attr qp_init_attr;
	struct ibv_device_attr dev_attr;

	/* This example assumes the alternate port we want to use is on the same
	 * HCA. Ports from other HCAs can be used as alternate paths as well. Get
	 * a list of devices using ibv_get_device_list or rdma_get_devices.
	 */
	ret = ibv_query_device(ctx->id->verbs, &dev_attr);
	if (ret) {
		VERB_ERR("ibv_query_device", ret);
		return ret;
	}

	/* Verify the APM is supported by the HCA */
	if (!(dev_attr.device_cap_flags | IBV_DEVICE_AUTO_PATH_MIG)) {
		printf("device does not support auto path migration!\n");
		return -1;
	}

	/* Query the QP to determine which port we are bound to */
	ret = ibv_query_qp(ctx->id->qp, &qp_attr, 0, &qp_init_attr);
	if (ret) {
		VERB_ERR("ibv_query_qp", ret);
		return ret;
	}

	for (i = 1; i < dev_attr.phys_port_cnt; i++) {
		/* Query all ports until we find one in the active state that is
		 * not the port we are currently connected to. */
		struct ibv_port_attr port_attr;
		ret = ibv_query_port(ctx->id->verbs, i, &port_attr);
		if (ret) {
			VERB_ERR("ibv_query_device", ret);
			return ret;
		}

		if (port_attr.state == IBV_PORT_ACTIVE) {
			ctx->my_alt_dlid = port_attr.lid;
			ctx->alt_srcport = i;
			if (qp_attr.port_num != i) {
				break;
			}
		}
	}

	return 0;
}

/* Function: load_alt_path
 *
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 *
 * Description:
 *  Uses ibv_modify_qp to load the alternate path information and set the
 *  path migraion state to rearm.
 */
int load_alt_path(struct context *ctx)
{
	int ret;
	struct ibv_qp_attr qp_attr;
	struct ibv_qp_init_attr qp_init_attr;

	/* query to get the current attributes of the qp */
	ret = ibv_query_qp(ctx->id->qp, &qp_attr, 0, &qp_init_attr);
	if (ret) {
		VERB_ERR("ibv_query_qp", ret);
		return ret;
	}

	/* initialize the alternate path attributes with the current path
	 * attributes */
	memcpy(&qp_attr.alt_ah_attr, &qp_attr.ah_attr, sizeof(struct ibv_ah_attr));

	/* set the alt path attributes to some baisc values */
	qp_attr.alt_pkey_index = qp_attr.pkey_index;
	qp_attr.alt_timeout = qp_attr.timeout;
	qp_attr.path_mig_state = IBV_MIG_REARM;

	/* if an alternate path was supplied, set the source port and the dlid */
	if (ctx->alt_srcport) {
		qp_attr.alt_port_num = ctx->alt_srcport;
	} else {
		qp_attr.alt_port_num = qp_attr.port_num;
	}

	if (ctx->alt_dlid) {
		qp_attr.alt_ah_attr.dlid = ctx->alt_dlid;
	}

	printf("loading alt path - local port: %d, dlid: %d\n",
		   qp_attr.alt_port_num, qp_attr.alt_ah_attr.dlid);

	ret = ibv_modify_qp(ctx->id->qp, &qp_attr,
						IBV_QP_ALT_PATH | IBV_QP_PATH_MIG_STATE);
	if (ret) {
		VERB_ERR("ibv_modify_qp", ret);
		return ret;
	}

	return 0;
}

/* Function: reg_mem
 *
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 *
 * Description:
 *  Registers memory regions to use for our data transfer
 */
int reg_mem(struct context *ctx)
{
	ctx->send_buf = (char*)malloc(ctx->msg_length);
	memset(ctx->send_buf, 0x12, ctx->msg_length);

	ctx->recv_buf = (char*)malloc(ctx->msg_length);
	memset(ctx->recv_buf, 0x00, ctx->msg_length);

	ctx->send_mr = rdma_reg_msgs(ctx->id, ctx->send_buf, ctx->msg_length);
	if (!ctx->send_mr) {
		VERB_ERR("rdma_reg_msgs", -1);
		return -1;
	}

	ctx->recv_mr = rdma_reg_msgs(ctx->id, ctx->recv_buf, ctx->msg_length);
	if (!ctx->recv_mr) {
		VERB_ERR("rdma_reg_msgs", -1);
		return -1;
	}

	return 0;
}

/* Function: getaddrinfo_and_create_ep
 *
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 *
 * Description:
 *  Gets the address information and creates our endpoint
 */
int getaddrinfo_and_create_ep(struct context *ctx)
{
	int ret;
	struct rdma_addrinfo *rai, hints;
	struct ibv_qp_init_attr qp_init_attr;

	memset(&hints, 0, sizeof(hints));
	hints.ai_port_space = RDMA_PS_TCP;
	if (ctx->server == 1) {
		/* This makes it a server */
		hints.ai_flags = RAI_PASSIVE;
	}

	printf("rdma_getaddrinfo\n");
	ret = rdma_getaddrinfo(ctx->server_name, ctx->server_port, &hints, &rai);
	if (ret) {
		VERB_ERR("rdma_getaddrinfo", ret);
		return ret;
	}

	memset(&qp_init_attr, 0, sizeof(qp_init_attr));
	qp_init_attr.cap.max_send_wr = 1;
	qp_init_attr.cap.max_recv_wr = 1;
	qp_init_attr.cap.max_send_sge = 1;
	qp_init_attr.cap.max_recv_sge = 1;

	printf("rdma_create_ep\n");
	ret = rdma_create_ep(&ctx->id, rai, NULL, &qp_init_attr);
	if (ret) {
		VERB_ERR("rdma_create_ep", ret);
		return ret;
	}

	rdma_freeaddrinfo(rai);
	return 0;
}

/* Function: get_conntext_request
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 *
 * Description:
 *  Wait for a connect request from the client
 */
int get_connect_request(struct context *ctx)
{
	int ret;

	printf("rdma_listen\n");
	ret = rdma_listen(ctx->id, 4);
	if (ret) {
		VERB_ERR("rdma_listen", ret);
		return ret;
	}

	ctx->listen_id = ctx->id;
	printf("rdma_get_request\n");
	ret = rdma_get_request(ctx->listen_id, &ctx->id);
	if (ret) {
		VERB_ERR("rdma_get_request", ret);
		return ret;
	}

	if (ctx->id->event->event != RDMA_CM_EVENT_CONNECT_REQUEST) {
		printf("unexpected event: %s",
				rdma_event_str(ctx->id->event->event));
		return ret;
	}

	/* If the alternate path info was not set on the command line, get
	   * it from the private data */
	if (ctx->alt_dlid == 0 && ctx->alt_srcport == 0) {
		ret = get_alt_dlid_from_private_data(ctx->id->event, &ctx->alt_dlid);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

/* Function: establish_connection
 *
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 *
 * Description:
 *  Create the connection. For the client, call rdma_connect. For the
 *  server, the connect request was already received, so just do
 *  rdma_accept to complete the connection.
 */
int establish_connection(struct context *ctx)
{
	int ret;
	uint16_t private_data;
	struct rdma_conn_param conn_param;

	/* post a receive to catch the first send */
	ret = rdma_post_recv(ctx->id, NULL, ctx->recv_buf, ctx->msg_length, ctx->recv_mr);
	if (ret) {
		VERB_ERR("rdma_post_recv", ret);
		return ret;
	}

	/* send the dlid for the alternate port in the private data */
	private_data = htons(ctx->my_alt_dlid);

	memset(&conn_param, 0, sizeof (conn_param));
	conn_param.private_data_len = sizeof (int);
	conn_param.private_data = &private_data;
	conn_param.responder_resources = 2;
	conn_param.initiator_depth = 2;
	conn_param.retry_count = 5;
	conn_param.rnr_retry_count = 5;

	if (ctx->server) {
		printf("rdma_accept\n");
		ret = rdma_accept(ctx->id, &conn_param);
		if (ret) {
			VERB_ERR("rdma_accept", ret);
			return ret;
		}
	} else {
		printf("rdma_connect\n");
		ret = rdma_connect(ctx->id, &conn_param);
		if (ret) {
			VERB_ERR("rdma_connect", ret);
			return ret;
		}

		if (ctx->id->event->event != RDMA_CM_EVENT_ESTABLISHED) {
			printf("unexpected event: %s", rdma_event_str(ctx->id->event->event));
			return -1;
		}

		/* If the alternate path info was not set on the command line, get
		 * it from the private data */
		if (ctx->alt_dlid == 0 && ctx->alt_srcport == 0) {
			ret = get_alt_dlid_from_private_data(ctx->id->event, &ctx->alt_dlid);
			if (ret)
				return ret;
		}
	}

	return 0;
}

/* Function: send_msg
 *
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 *
 * Description:
 *  Performs an Send and gets the completion
 */
int send_msg(struct context *ctx)
{
	int ret;
	struct ibv_wc wc;

	ret = rdma_post_send(ctx->id, NULL, ctx->send_buf, ctx->msg_length, ctx->send_mr, IBV_SEND_SIGNALED);
	if (ret) {
		VERB_ERR("rdma_send_recv", ret);
		return ret;
	}

	ret = rdma_get_send_comp(ctx->id, &wc);
	if (ret < 0) {
		VERB_ERR("rdma_get_send_comp", ret);
		return ret;
	}

	return 0;
}

/* Function: recv_msg
 *
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 *
 * Description:
 *  Waits for a receive completion and posts a new receive buffer
 */
int recv_msg(struct context *ctx)
{
	int ret;
	struct ibv_wc wc;

	ret = rdma_get_recv_comp(ctx->id, &wc);
	if (ret < 0) {
		VERB_ERR("rdma_get_recv_comp", ret);
		return ret;
	}

	ret = rdma_post_recv(ctx->id, NULL, ctx->recv_buf, ctx->msg_length, ctx->recv_mr);
	if (ret) {
		VERB_ERR("rdma_post_recv", ret);
		return ret;
	}

	return 0;
}

/* Function: main
 *
 * Input:
 *  ctx  The context object
 *
 * Output:
 *  none
 *
 * Returns:
 *  0 on success, non-zero on failure
 */
int main(int argc, char** argv)
{
	int ret, op, i, send_cnt, recv_cnt;
	struct context ctx;
	struct ibv_qp_attr qp_attr;

	memset(&ctx, 0, sizeof (ctx));
	memset(&qp_attr, 0, sizeof (qp_attr));

	ctx.server = 0;
	ctx.server_port = DEFAULT_PORT;
	ctx.msg_count = DEFAULT_MSG_COUNT;
	ctx.msg_length = DEFAULT_MSG_LENGTH;
	ctx.msec_delay = DEFAULT_MSEC_DELAY;
	ctx.alt_dlid = 0;
	ctx.alt_srcport = 0;
	ctx.migrate_after = -1;

	while ((op = getopt(argc, argv, "sa:p:c:l:d:r:m:")) != -1) {
		switch (op) {
		case 's':
			ctx.server = 1;
			break;
		case 'a':
			ctx.server_name = optarg;
			break;
		case 'p':
			ctx.server_port = optarg;
			break;
		case 'c':
			ctx.msg_count = atoi(optarg);
			break;
		case 'l':
			ctx.msg_length = atoi(optarg);
			break;
		case 'd':
			ctx.alt_dlid = atoi(optarg);
			break;
		case 'r':
			ctx.alt_srcport = atoi(optarg);
			break;
		case 'm':
			ctx.migrate_after = atoi(optarg);
			break;
		case 'w':
			ctx.msec_delay = atoi(optarg);
			break;
		default:
			printf("usage: %s [-s or -a required]\n", argv[0]);
			printf("\t[-s[erver mode]\n");
			printf("\t[-a ip_address]\n");
			printf("\t[-p port_number]\n");
			printf("\t[-c msg_count]\n");
			printf("\t[-l msg_length]\n");
			printf("\t[-d alt_dlid] (requires -r)\n");
			printf("\t[-r alt_srcport] (requires -d)\n");
			printf("\t[-m num_iterations_then_migrate] (client only)\n");
			printf("\t[-w msec_wait_between_sends]\n");
			exit(1);
		}
	}

	printf("mode: %s\n", (ctx.server) ? "server" : "client");
	printf("address: %s\n", (!ctx.server_name) ? "NULL" : ctx.server_name);
	printf("port: %s\n", ctx.server_port);
	printf("count: %d\n", ctx.msg_count);
	printf("length: %d\n", ctx.msg_length);
	printf("alt_dlid: %d\n", ctx.alt_dlid);
	printf("alt_port: %d\n", ctx.alt_srcport);
	printf("mig_after: %d\n", ctx.migrate_after);
	printf("msec_wait: %d\n", ctx.msec_delay);
	printf("\n");

	if (!ctx.server && !ctx.server_name) {
		printf("server address must be specified for client mode\n");
		exit(1);
	}

	/* both of these must be set or neither should be set */
	if (!((ctx.alt_dlid > 0 && ctx.alt_srcport > 0) || (ctx.alt_dlid == 0 && ctx.alt_srcport == 0))) {
		printf("-d and -r must be used together\n");
		exit(1);
	}

	if (ctx.migrate_after > ctx.msg_count) {
		printf("num_iterations_then_migrate must be less than msg_count\n");
		exit(1);
	}

	ret = getaddrinfo_and_create_ep(&ctx);
	if (ret) {
		goto out;
	}

	if (ctx.server) {
		ret = get_connect_request(&ctx);
		if (ret) {
			goto out;
		}
	}

	/* only query for alternate port if information was not specified on the
	 * command line */
	if (ctx.alt_dlid == 0 && ctx.alt_srcport == 0) {
		ret = get_alt_port_details(&ctx);
		if (ret) {
			goto out;
		}
	}

	/* create a thread to handle async events */
	pthread_create(&ctx.async_event_thread, NULL, async_event_thread, &ctx);

	ret = reg_mem(&ctx);
	if (ret) {
		goto out;
	}

	ret = establish_connection(&ctx);

	/* load the alternate path after the connection was created. This can be
	 * done at connection time, but the connection must be created and
	 * established using all ib verbs */
	ret = load_alt_path(&ctx);
	if (ret) {
		goto out;
	}

	send_cnt = recv_cnt = 0;

	for (i = 0; i < ctx.msg_count; i++) {
		if (ctx.server) {
			if (recv_msg(&ctx)) {
				break;
			}

			printf("recv: %d\n", ++recv_cnt);
		}

		if (ctx.msec_delay > 0) {
			usleep(ctx.msec_delay * 1000);
		}

		if (send_msg(&ctx)) {
			break;
		}

		printf("send: %d\n", ++send_cnt);

		if (!ctx.server) {
			if (recv_msg(&ctx)) {
				break;
			}

			printf("recv: %d\n", ++recv_cnt);
		}

		/* migrate the path manually if desired after the specified number of
		 * sends */
		if (!ctx.server && i == ctx.migrate_after) {
			qp_attr.path_mig_state = IBV_MIG_MIGRATED;
			ret = ibv_modify_qp(ctx.id->qp, &qp_attr, IBV_QP_PATH_MIG_STATE);
			if (ret) {
				VERB_ERR("ibv_modify_qp", ret);
				goto out;
			}
		}
	}

	rdma_disconnect(ctx.id);

out:
	if (ctx.send_mr) {
		rdma_dereg_mr(ctx.send_mr);
	}

	if (ctx.recv_mr) {
		rdma_dereg_mr(ctx.recv_mr);
	}

	if (ctx.id) {
		rdma_destroy_ep(ctx.id);
	}

	if (ctx.listen_id) {
		rdma_destroy_ep(ctx.listen_id);
	}

	if (ctx.send_buf) {
		free(ctx.send_buf);
	}

	if (ctx.recv_buf) {
		free(ctx.recv_buf);
	}

	return ret;
}
