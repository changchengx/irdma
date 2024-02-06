/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

/*
 * $ show_gids
 * DEV     PORT    INDEX   GID                                     IPv4            VER     DEV
 * ---     ----    -----   ---                                     ------------    ---     ---
 * mlx5_2  1       0       fe80:0000:0000:0000:00c3:1eff:fe76:e5bf                 v2      enp3s0f0s0
 * mlx5_2  1       1       0000:0000:0000:0000:0000:ffff:c0a8:1e15 192.168.30.21   v2      enp3s0f0s0
 * mlx5_3  1       0       fe80:0000:0000:0000:003b:b8ff:fe8b:72c8                 v2      enp3s0f1s0
 *
 * # server read data from server and verify invalidate cache w/o writeback function
 * # gcc -I${RDMA_PATH}build/include -L${RDMA_PATH}build/lib read_remote_inv_cache.c -libverbs -lmlx5 -o read_remote_inv_cache
 * # server(192.168.30.21) taskset -c 8 ./rd_connect_mma mlx5_2 -i
 * # client(192.168.30.20) taskset -c 8 ./rd_connect_mma mlx5_2 -n 192.168.30.21
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

// Note: Change if it's needed
#define GID_INDEX 1

#define MR_LEN (2 * 1024 * 1024)
#define SLEEP_NANO (10 * 1000)

typedef struct {
	char *server_name;
	uint16_t server_port;
	sa_family_t ai_family;
	uint32_t server_inv_cache;
} cmd_args_t;

struct ibv_device* get_device(const char*dev_name)
{
	struct ibv_device ** device_list = ibv_get_device_list(NULL);
	struct ibv_device *device;

	for (device = *device_list; device != NULL; device = *(++device_list)) {
		if (strcmp(dev_name, ibv_get_device_name(device)) == 0) {
			break;
		}
	}

	if (device == NULL) {
		printf("failed to get device\n");
		exit(__LINE__);
	}

	return device;
}

struct ibv_context* create_ctx(struct ibv_device *ibv_dev)
{
	struct mlx5dv_context_attr dv_attr = {};

	dv_attr.flags |= MLX5DV_CONTEXT_FLAGS_DEVX;
	struct ibv_context *ctxt = mlx5dv_open_device(ibv_dev, &dv_attr);

	if (ctxt == NULL) {
		printf("failed to create context\n");
		exit(__LINE__);
	}

	return ctxt;
}

uint32_t check_basic_cap(struct ibv_context *ibv_ctx)
{
	struct ibv_device_attr dev_attr = {};

	if (ibv_query_device(ibv_ctx, &dev_attr)) {
		printf("failed to query device basic attr\n");
		exit(__LINE__);
	}

	if (dev_attr.max_qp_wr < 256) {
		printf("max_qp_wr is %d\n", dev_attr.max_qp_wr);
		exit(__LINE__);
	}

	return 0;
}

uint32_t get_port_num(struct ibv_context *ibv_ctx)
{
	struct ibv_device_attr dev_attr = {};

	if (ibv_query_device(ibv_ctx, &dev_attr)) {
		printf("failed to query device basic attr\n");
		exit(__LINE__);
	}

	return dev_attr.phys_port_cnt;
}

uint32_t get_port_attr(struct ibv_context *ibv_ctx,
		struct ibv_port_attr *port_attr, uint8_t port_num)
{
	if (port_num != get_port_num(ibv_ctx)) {
		exit(__LINE__);
	}

	if (ibv_query_port(ibv_ctx, port_num, port_attr) ||
		port_attr->state != IBV_PORT_ACTIVE ||
		port_attr->link_layer != IBV_LINK_LAYER_ETHERNET) {
		printf("failed to query active port attr\n");
		exit(__LINE__);
	}

	return 0;
}

struct ibv_pd* get_ibv_pd(struct ibv_context *ibv_ctx)
{
	struct ibv_pd* pd = ibv_alloc_pd(ibv_ctx);

	if (pd) {
		printf("failed to alloc pd\n");
		exit(__LINE__);
	}

	return pd;
}

struct ibv_mr* create_one_mr(struct ibv_pd *pd, uint32_t mr_len)
{
	struct ibv_mr* reg_mr = NULL;
	void *alloc_region = NULL;

	if (posix_memalign(&alloc_region, sysconf(_SC_PAGESIZE), mr_len)) {
		printf("failed to alloc %d mem size\n", mr_len);
		exit(__LINE__);
	}

	reg_mr = ibv_reg_mr(pd, alloc_region, mr_len,
				IBV_ACCESS_LOCAL_WRITE | \
				IBV_ACCESS_RELAXED_ORDERING |\
				IBV_ACCESS_REMOTE_READ);
	if (NULL == reg_mr) {
		printf("failed to reg MR\n");
		exit(__LINE__);
	}

	return reg_mr;
}

struct ibv_mr** create_three_mr(struct ibv_pd *pd, uint32_t mr_len)
{
	struct ibv_mr **mrs = calloc(3, sizeof(struct ibv_mr*));

	if (NULL == mrs) {
		printf("failed to alloc 2 MR pointer\n");
		exit(__LINE__);
	}

	mrs[0] = create_one_mr(pd, mr_len);
	mrs[1] = create_one_mr(pd, mr_len);
	mrs[2] = create_one_mr(pd, mr_len);

	return mrs;
}

struct ibv_cq* create_cq(struct ibv_context *ibv_ctx)
{
	struct ibv_cq_init_attr_ex cq_attr = {
		.cqe = 256,
		.cq_context = NULL,
		.channel = NULL,
		.comp_vector = 0
	};

	struct ibv_cq_ex *cq_ex = mlx5dv_create_cq(ibv_ctx, &cq_attr, NULL);
	if (NULL == cq_ex) {
		printf("failed to create cq\n");
		exit(__LINE__);
	}

	return ibv_cq_ex_to_cq(cq_ex);
}

struct ibv_qp* create_qp(struct ibv_context *ibv_ctx, struct ibv_pd* pd)
{
	struct ibv_cq *rq_cq = create_cq(ibv_ctx);
	struct ibv_cq *sq_cq = create_cq(ibv_ctx);

	struct ibv_qp_cap qp_cap = {
		.max_send_wr = 256,
		.max_recv_wr = 256,
		.max_send_sge = 1,
		.max_recv_sge = 1,
		.max_inline_data = 64
	};

	struct ibv_qp_init_attr_ex init_attr = {
		.qp_context = NULL,
		.sq_sig_all = 0,
		.send_cq = sq_cq,
		.recv_cq = rq_cq,
		.cap = qp_cap,

		.qp_type = IBV_QPT_RC,
		.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
		.pd = pd,
		.send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM | \
				IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_SEND_WITH_IMM | IBV_QP_EX_WITH_RDMA_READ,
	};

	struct mlx5dv_qp_init_attr attr_dv = {
		.comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS,
		.send_ops_flags = MLX5DV_QP_EX_WITH_MEMCPY,
	};

	struct ibv_qp *qp = mlx5dv_create_qp(ibv_ctx, &init_attr, &attr_dv);
	if (NULL == qp) {
		printf("failed to create qp\n");
	}

	struct ibv_qp_attr qpa = {};
	struct ibv_qp_init_attr qpia = {};
	if (ibv_query_qp(qp, &qpa, IBV_QP_CAP, &qpia)) {
		printf("failed to query qp cap\n");
		exit(__LINE__);
	}

	printf("create qp with qpn = 0x%x, max_send_wr = 0x%x, max_recv_wr = 0x%x, "
		"max_send_sge = 0x%x, max_recv_sge = 0x%x, max_inline_data = 0x%x\n",
		qp->qp_num, qpa.cap.max_send_wr, qpa.cap.max_recv_wr, qpa.cap.max_send_sge,
		qpa.cap.max_recv_sge, qpa.cap.max_inline_data);

	return qp;
}

uint32_t init_qp(struct ibv_qp *qp)
{
	if (qp == NULL) {
		return 0;
	}

	enum ibv_qp_attr_mask mask = IBV_QP_STATE | IBV_QP_PORT | IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS;
	struct ibv_qp_attr attr = {
		.qp_state = IBV_QPS_INIT,
		.pkey_index = 0,
		.port_num = 1,
		.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ,
	};

	if (ibv_modify_qp(qp, &attr, mask)) {
		printf("failed to modify qp:0x%x to init\n", qp->qp_num);
		exit(__LINE__);
	}

	return 0;
}

uint32_t query_gid_lid(struct ibv_context *ibv_ctx, union ibv_gid *gid, uint16_t *lid)
{
	struct ibv_port_attr port_attr = {};

	if (get_port_attr(ibv_ctx, &port_attr, 1)) {
		printf("failed to query port attr\n");
		exit(__LINE__);
	}
	*lid = port_attr.lid;

	if (ibv_query_gid(ibv_ctx, 1, GID_INDEX, gid)) {
		printf("failed to query port gid\n");
		exit(__LINE__);
	}

	return 0;
}

uint32_t qp_self_connected(struct ibv_qp* qp)
{
	if (qp == NULL) {
		return 0;
	}
	union ibv_gid gid = {};
	uint16_t lid = 0;
	query_gid_lid(qp->context, &gid, &lid);

	enum ibv_qp_attr_mask mask = IBV_QP_STATE | IBV_QP_AV | \
		IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | \
		IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
	struct ibv_qp_attr qpa = {
		.qp_state = IBV_QPS_RTR,
		.path_mtu = IBV_MTU_1024,
		.dest_qp_num = qp->qp_num,
		.rq_psn = 0,
		.max_dest_rd_atomic = 1,
		.min_rnr_timer = 0x12,
		.ah_attr = {
			.is_global = 1,
			.port_num = 1,
			.grh = {
				.hop_limit = 64,
				.sgid_index = GID_INDEX,
				.dgid = gid
			}
		}
	};

	if (ibv_modify_qp(qp, &qpa, mask)) {
		printf("failed to modify qp:0x%x to rtr, errno 0x%x\n", qp->qp_num, errno);
		exit(__LINE__);
	}

	qpa.qp_state   = IBV_QPS_RTS;
	qpa.timeout    = 12;
	qpa.retry_cnt  = 6;
	qpa.rnr_retry  = 0;
	qpa.sq_psn     = 0;
	qpa.max_rd_atomic  = 1;
	mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |\
		IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
	if (ibv_modify_qp(qp, &qpa, mask)) {
		printf("failed to modify qp:0x%x to rts, errno 0x%x\n", qp->qp_num, errno);
		exit(__LINE__);
	}
	return 0;
}

uint32_t normal_traffic(struct ibv_qp *qp, struct ibv_mr *local_mr, struct ibv_mr *remote_mr, uint32_t offset, uint32_t is_server)
{
	struct ibv_send_wr sq_wr = {}, *bad_wr_send = NULL;
	struct ibv_sge sq_wr_sge = {};
	struct ibv_mr *sq_mr = local_mr;
	struct ibv_mr *rq_mr = remote_mr;

	if (is_server == 0) {
		// server read data from client;
		return 0;
	}
	sq_wr_sge.lkey = sq_mr->lkey;
	sq_wr_sge.addr = (uint64_t)sq_mr->addr + offset;
	sq_wr_sge.length = MR_LEN;

	sq_wr.next = NULL;
	sq_wr.wr_id = 0x31415926;
	sq_wr.send_flags = IBV_SEND_SIGNALED;
	sq_wr.opcode = IBV_WR_RDMA_READ;
	sq_wr.sg_list = &sq_wr_sge;
	sq_wr.num_sge = 1;
	sq_wr.wr.rdma.remote_addr = (uint64_t)rq_mr->addr + offset;
	sq_wr.wr.rdma.rkey = rq_mr->rkey;

	if (ibv_post_send(qp, &sq_wr, &bad_wr_send)) {
		printf("failed to exec rdma_write\n");
		exit(__LINE__);
	}

	struct ibv_wc wc = {};
	while (ibv_poll_cq(qp->send_cq, 1, &wc) == 0) {
		continue;
	}

	if (wc.status != IBV_WC_SUCCESS || wc.wr_id != 0x31415926) {
		printf("failed to exec rdma_write with wrong cqe\n");
		exit(__LINE__);
	}

	return 0;
}

uint32_t local_dma_copy(struct ibv_qp *qp, struct ibv_mr **mrs)
{
	uint32_t dma_len = MR_LEN;
	struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(qp);
	struct mlx5dv_qp_ex* mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
	struct ibv_mr *sq_mr = mrs[1];
	struct ibv_mr *rq_mr = mrs[2];
	uint64_t rq_dest_addr = (uint64_t)rq_mr->addr;

	ibv_wr_start(qpx);
	qpx->wr_id = 0x27182818;
	qpx->wr_flags = IBV_SEND_SIGNALED;
	mlx5dv_wr_memcpy(mqpx, rq_mr->lkey, rq_dest_addr, sq_mr->lkey, (uint64_t)sq_mr->addr, dma_len);
	if (ibv_wr_complete(qpx)) {
		printf("failed to exe memcpy\n");
		exit(__LINE__);
	}

	struct ibv_wc wc = {};
	while (ibv_poll_cq(qp->send_cq, 1, &wc) == 0) {
		continue;
	}

	if (wc.status != IBV_WC_SUCCESS) {
		printf("error cqe, status:%s, vendor_err:0x%08x, opcode:0x%08x, wr_id:0x%016lx\n",
		        ibv_wc_status_str(wc.status), wc.vendor_err, wc.opcode, wc.wr_id);
		exit(__LINE__);
	}

	return 0;
}

int timeval_subtract(struct timeval *result, struct timeval *end, struct timeval *start)
{
	/* Perform the carry for the later subtraction by updating y. */
	if (end->tv_usec < start->tv_usec) {
		int nsec = (start->tv_usec - end->tv_usec) / 1000000 + 1;
		start->tv_usec -= 1000000 * nsec;
		start->tv_sec += nsec;
	}

	if (end->tv_usec - start->tv_usec > 1000000) {
		int nsec = (end->tv_usec - start->tv_usec) / 1000000;
		start->tv_usec += 1000000 * nsec;
		start->tv_sec -= nsec;
	}

	/* Compute the time remaining to wait.
	 * tv_usec is certainly positive. */
	result->tv_sec = end->tv_sec - start->tv_sec;
	result->tv_usec = end->tv_usec - start->tv_usec;

	/* Return 1 if result is negative. */
	return end->tv_sec < start->tv_sec;
}

void sleep_nano_seconds(uint64_t nanos, struct timeval *elpase)
{
	struct timespec sleep_time = {0, nanos};
	if (elpase) {
		if (elpase->tv_usec * 1000 < nanos) {
			sleep_time.tv_nsec -= elpase->tv_usec * 1000;
		} else {
			return;
		}
	}

	nanosleep(&sleep_time, NULL);
}

uint32_t local_cache_invalid(struct ibv_qp *qp, struct ibv_mr *mr, uint32_t offset, bool need_writeback)
{
	struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(qp);
	struct mlx5dv_qp_ex* mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
	uint64_t volatile *addr = (uint64_t*)mr->addr;
	uint64_t sleep_nano = 0;

	ibv_wr_start(qpx);
	qpx->wr_id = 0x33219280;
	qpx->wr_flags = IBV_SEND_SIGNALED;

	mlx5dv_wr_invcache(mqpx, mr->lkey, (uint64_t)mr->addr + offset, MR_LEN, need_writeback);
	if (ibv_wr_complete(qpx)) {
		printf("failed to exe invcache\n");
		exit(__LINE__);
	}

	struct ibv_wc wc = {};
	while (ibv_poll_cq(qp->send_cq, 1, &wc) == 0) {
		continue;
	}

	if (wc.status != IBV_WC_SUCCESS) {
		printf("error cqe, status:%s, vendor_err:0x%08x, opcode:0x%08x, wr_id:0x%016lx\n",
		        ibv_wc_status_str(wc.status), wc.vendor_err, wc.opcode, wc.wr_id);
		exit(__LINE__);
	}

	return 0;
}

int parse_cmd(int argc, char * const argv[], cmd_args_t *args)
{
	int c = 0, idx = 0;

	memset(args, 0, sizeof(*args));

	/* Defaults */
	args->server_port   = 13337;
	args->ai_family     = AF_INET;

	while ((c = getopt(argc, argv, "i6:n:p")) != -1) {
		switch (c) {
		case 'n':
			args->server_name = optarg;
			break;
		case '6':
			args->ai_family = AF_INET6;
			break;
		case 'i':
			args->server_inv_cache = 1;
			break;
		case 'p':
			args->server_port = atoi(optarg);
			if (args->server_port <= 0) {
				fprintf(stderr, "Wrong server port number %d\n", args->server_port);
				exit(__LINE__);
			}
			break;
		}
	}

	return 0;
}

int connect_common(const char *server, uint16_t server_port, sa_family_t af)
{
	int sockfd   = -1;
	int listenfd = -1;
	int optval   = 1;
	char service[8];
	struct addrinfo hints, *res, *t;
	int ret;

	snprintf(service, sizeof(service), "%u", server_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags    = (server == NULL) ? AI_PASSIVE : 0;
	hints.ai_family   = af;
	hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(server, service, &hints, &res);
	if (ret < 0) {
		printf("getaddrinfo() failed\n");
		exit(__LINE__);
	}

	for (t = res; t != NULL; t = t->ai_next) {
		sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
		if (sockfd < 0) {
			continue;
		}

		if (server != NULL) {
			if (connect(sockfd, t->ai_addr, t->ai_addrlen) == 0)
				break;
		} else {
			ret = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
			if (ret < 0) {
				printf("server setsockopt()\n");
				exit(__LINE__);
			}

			if (bind(sockfd, t->ai_addr, t->ai_addrlen) == 0) {
				ret = listen(sockfd, 0);
				if (ret < 0) {
					printf("listen server\n");
					exit(__LINE__);
				}

				/* Accept next connection */
				fprintf(stdout, "Waiting for connection...\n");
				listenfd = sockfd;
				sockfd   = accept(listenfd, NULL, NULL);
				close(listenfd);
				break;
			}
		}

		close(sockfd);
		sockfd = -1;
	}

	if (sockfd < 0) {
		printf("%s failed\n", (server) ? "open client socket" : "open server socket");
		exit(__LINE__);
	}

out_free_res:
    freeaddrinfo(res);
out:
    return sockfd;
}

int sendrecv(int sock, const void *sbuf, size_t slen, void **rbuf)
{
	int ret = 0;
	size_t rlen = 0;
	*rbuf = NULL;

	ret = send(sock, &slen, sizeof(slen), 0);

	if ((ret < 0) || (ret != sizeof(slen))) {
		fprintf(stderr, "failed to send buffer length\n");
		return -1;
	}

	ret = send(sock, sbuf, slen, 0);
	if (ret != (int)slen) {
		fprintf(stderr, "failed to send buffer, return value %d\n", ret);
		return -1;
	}

	ret = recv(sock, &rlen, sizeof(rlen), MSG_WAITALL);
	if ((ret != sizeof(rlen)) || (rlen > (SIZE_MAX / 2))) {
		fprintf(stderr, "failed to receive device address length, return value %d\n", ret);
		return -1;
	}

	*rbuf = calloc(1, rlen);
	if (!*rbuf) {
		fprintf(stderr, "failed to allocate receive buffer\n");
		return -1;
	}

	ret = recv(sock, *rbuf, rlen, MSG_WAITALL);
	if (ret != (int)rlen) {
		fprintf(stderr, "failed to receive device address, return value %d\n", ret);
		return -1;
	}

	return 0;
}

uint32_t qp_remote_connected(struct ibv_qp* qp, struct ibv_mr* local_mr, struct ibv_mr *remote_mr, int oob_sock)
{
	union ibv_gid local_gid = {};
	uint16_t local_lid = 0;
	query_gid_lid(qp->context, &local_gid, &local_lid);

	void *encode = calloc(1, sizeof(qp->qp_num) + sizeof(local_gid) + sizeof(*local_mr));
	memcpy(encode, &qp->qp_num, sizeof(qp->qp_num));
	memcpy(encode + sizeof(qp->qp_num), &local_gid, sizeof(local_gid));
	memcpy(encode + sizeof(qp->qp_num) + sizeof(local_gid), local_mr, sizeof(*local_mr));
	void *decode = NULL;
	sendrecv(oob_sock, encode, sizeof(qp->qp_num) + sizeof(local_gid) + sizeof(*local_mr), &decode);

	union ibv_gid remote_gid = {};
	uint32_t remote_qpn = 0;
	memcpy(&remote_qpn, decode, sizeof(qp->qp_num));
	memcpy(&remote_gid, decode + sizeof(qp->qp_num), sizeof(remote_gid));
	memcpy(remote_mr, decode + sizeof(qp->qp_num) + sizeof(local_gid), sizeof(*local_mr));
	free(decode);

	enum ibv_qp_attr_mask mask = IBV_QP_STATE | IBV_QP_AV | \
		IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | \
		IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
	struct ibv_qp_attr qpa = {
		.qp_state = IBV_QPS_RTR,
		.path_mtu = IBV_MTU_1024,
		.dest_qp_num = remote_qpn,
		.rq_psn = 0,
		.max_dest_rd_atomic = 1,
		.min_rnr_timer = 0x12,
		.ah_attr = {
			.is_global = 1,
			.port_num = 1,
			.grh = {
				.hop_limit = 64,
				.sgid_index = GID_INDEX,
				.dgid = remote_gid
			}
		}
	};

	if (ibv_modify_qp(qp, &qpa, mask)) {
		printf("failed to modify qp:0x%x to rtr, errno 0x%x\n", qp->qp_num, errno);
		exit(__LINE__);
	}

	qpa.qp_state   = IBV_QPS_RTS;
	qpa.timeout    = 12;
	qpa.retry_cnt  = 6;
	qpa.rnr_retry  = 0;
	qpa.sq_psn     = 0;
	qpa.max_rd_atomic  = 1;
	mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |\
		IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
	if (ibv_modify_qp(qp, &qpa, mask)) {
		printf("failed to modify qp:0x%x to rts, errno 0x%x\n", qp->qp_num, errno);
		exit(__LINE__);
	}
	return 0;
}

void client_send_syn(int sock, int is_server, uint32_t sync_oob)
{
	if (is_server)
		return;

	//client send sync to server
	int ret = 0;
	uint32_t sync = (7 << 28) + sync_oob;

	ret = send(sock, &sync, sizeof(sync), 0);

	if ((ret < 0) || (ret != sizeof(sync))) {
		fprintf(stderr, "client failed to send sync to server\n");
		exit(__LINE__);
	}
}

void server_wait_syn(int sock, int is_server, uint32_t wait_oob)
{
	if (!is_server)
		return;

	//server wait sync from client
	int ret = 0;
	uint32_t wait_sync = 0;

	ret = recv(sock, &wait_sync, sizeof(wait_sync), MSG_WAITALL);
	if ((ret != sizeof(wait_sync)) || (wait_sync >> 28) != 7 || (wait_sync & 0xfffffff) != wait_oob) {
		fprintf(stderr, "server failed to get sync from client\n");
		exit(__LINE__);
	}
}

void server_send_ack(int sock, int is_server, uint32_t ack_oob)
{
	if (!is_server)
		return;

	//server send ack to client
	int ret = 0;
	uint32_t ack = (8 << 28) + ack_oob;

	ret = send(sock, &ack, sizeof(ack), 0);

	if ((ret < 0) || (ret != sizeof(ack))) {
		fprintf(stderr, "server failed to send ack to client\n");
		exit(__LINE__);
	}
}

void client_wait_ack(int sock, int is_server, uint32_t wait_oob)
{
	if (is_server)
		return;

	//client wait ack from server
	int ret = 0;
	uint32_t wait_ack = 0;

	ret = recv(sock, &wait_ack, sizeof(wait_ack), MSG_WAITALL);
	if ((ret != sizeof(wait_ack)) || (wait_ack >> 28) != 8 || (wait_ack & 0xfffffff) != wait_oob) {
		fprintf(stderr, "client failed to get ack from server\n");
		exit(__LINE__);
	}
}

void fence(int sock, int is_server, uint32_t oob_value)
{
	client_send_syn(sock, is_server, oob_value);
	server_wait_syn(sock, is_server, oob_value);
	server_send_ack(sock, is_server, oob_value + 1);
	client_wait_ack(sock, is_server, oob_value + 1);
}

void sw_flush_cache(void)
{
	uint32_t len = 32 * 1024 * 1024;
	uint32_t *addr = malloc(len);

	for (uint32_t i = 0; i < 8; i++) {
		memset(addr, 0, len);
	}
	free(addr);
}

void server_inv_cache_or_sleep(struct ibv_qp *qp, struct ibv_mr *mr, uint32_t offset, int is_server, int inv_cache)
{
	if (!is_server)
		return;

	if (!inv_cache) {
		sleep_nano_seconds(SLEEP_NANO, NULL);
	} else {
		struct timeval start, end, elpase;
		gettimeofday(&start, NULL);

		local_cache_invalid(qp, mr, offset, 0);

		gettimeofday(&end, NULL);
		timeval_subtract(&elpase, &end, &start);
		sleep_nano_seconds(SLEEP_NANO, &elpase);
	}
}

int main(int argc, char *argv[])
{
	struct ibv_device *ibv_dev = get_device(argv[1]);
	struct ibv_context *ibv_ctx = create_ctx(ibv_dev);
	struct ibv_pd* pd = ibv_alloc_pd(ibv_ctx);
	struct ibv_mr* mr = create_one_mr(pd, MR_LEN * 8); //mr
	struct ibv_mr remote_mr = {};

	cmd_args_t cmd_args = {};
	parse_cmd(argc, argv, &cmd_args);
	int is_server = cmd_args.server_name == NULL;
	int oob_sock = connect_common(cmd_args.server_name, cmd_args.server_port, cmd_args.ai_family);

	struct ibv_qp *qp = create_qp(ibv_ctx, pd); // connect with peer;
	init_qp(qp);
	qp_remote_connected(qp, mr, &remote_mr, oob_sock);

	struct ibv_qp *inv_cache_qp = is_server ? create_qp(ibv_ctx, pd) : NULL; // self connected to send GGA/MMA;
	init_qp(inv_cache_qp);
	qp_self_connected(inv_cache_qp);

	if (!is_server) {
		// client set old value at mr->addr[0];
		*(uint64_t*)mr->addr = 0xdeadbeefcafeabcd;
	} else {
		// server clear value at mr->addr[0];
		*(uint64_t*)mr->addr = 0;
	}

	fence(oob_sock, is_server, 1);
	sw_flush_cache();

	// server RDMA_READ client's mr[0, MR_LEN} to server's mr[0, MR_LEN}
	normal_traffic(qp, mr, &remote_mr, 0, is_server);
	if (is_server && *(uint64_t*)mr->addr != 0xdeadbeefcafeabcd) {
		// server got old value
		printf("server 1st get unexpected value 0x%016lx\n", *(uint64_t*)mr->addr);
		exit(__LINE__);
	}

	fence(oob_sock, is_server, 3);
	if (!is_server) {
		// client set new value at mr->addr[0];
		*(uint64_t*)mr->addr = 0xabcdcafebeefdead;
	}
	fence(oob_sock, is_server, 5);
	sw_flush_cache();

	// server RDMA_READ client's mr[0, MR_LEN} to server's mr[0, MR_LEN}
	normal_traffic(qp, mr, &remote_mr, 0, is_server);
	server_inv_cache_or_sleep(inv_cache_qp, mr, 0, is_server, cmd_args.server_inv_cache);
	if (is_server && cmd_args.server_inv_cache && *(uint64_t*)mr->addr == 0xdeadbeefcafeabcd) {
		// server still got old value
		printf("server pass GGA/MMA test\n");
	} else if (is_server && cmd_args.server_inv_cache) {
		printf("server 2nd get unexpected value 0x%016lx\n", *(uint64_t*)mr->addr);
		exit(__LINE__);
	}

	fence(oob_sock, is_server, 7);
	return 0;
}
