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
 * $ gcc -I${RDMA_PATH}build/include -L${RDMA_PATH}build/lib gga_mma.c -libverbs -lmlx5 -o gga_mma
 * $ ./gga_mma mlx5_2
 * $ ./gga_mma mlx5_2 inv
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

// Note: Change if it's needed
#define GID_INDEX 1

#define MR_LEN (2 * 1024 * 1024)
#define SLEEP_NANO (40 * 1000)

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
				IBV_ACCESS_REMOTE_READ | \
				IBV_ACCESS_REMOTE_WRITE);
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

struct ibv_qp* create_qp(struct ibv_context *ibv_ctx,
	struct ibv_pd* pd, struct ibv_cq *rq_cq, struct ibv_cq *sq_cq)
{
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

uint32_t normal_traffic(struct ibv_qp *qp, struct ibv_mr **mrs)
{
	struct ibv_send_wr sq_wr = {}, *bad_wr_send = NULL;
	struct ibv_sge sq_wr_sge = {};
	struct ibv_mr *sq_mr = mrs[0];
	struct ibv_mr *rq_mr = mrs[1];

	sq_wr_sge.lkey = sq_mr->lkey;
	sq_wr_sge.addr = (uint64_t)sq_mr->addr;
	sq_wr_sge.length = MR_LEN;

	sq_wr.next = NULL;
	sq_wr.wr_id = 0x31415926;
	sq_wr.send_flags = IBV_SEND_SIGNALED;
	sq_wr.opcode = IBV_WR_RDMA_WRITE;
	sq_wr.sg_list = &sq_wr_sge;
	sq_wr.num_sge = 1;
	sq_wr.wr.rdma.remote_addr = (uint64_t)rq_mr->addr;
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

int timeval_subtract (struct timeval *result, struct timeval *end, struct timeval *start)
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
		sleep_time.tv_nsec - elpase->tv_usec * 1000;
	}

	nanosleep(&sleep_time, NULL);
}

uint32_t local_cache_invalid(struct ibv_qp *qp, struct ibv_mr *mr, bool need_writeback)
{
	struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(qp);
	struct mlx5dv_qp_ex* mqpx = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
	uint64_t volatile *addr = (uint64_t*)mr->addr;
	struct timeval start, end, elpase;
	uint64_t sleep_nano = 0;

	gettimeofday(&start, NULL);

	ibv_wr_start(qpx);
	qpx->wr_id = 0x33219280;
	qpx->wr_flags = IBV_SEND_SIGNALED;

	mlx5dv_wr_invcache(mqpx, mr->lkey, (uint64_t)mr->addr, MR_LEN, need_writeback); // #TODO: confirm supported length
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

	gettimeofday(&end, NULL);
	timeval_subtract (&elpase, &end, &start);
	sleep_nano_seconds(SLEEP_NANO, &elpase);

	return 0;
}

void sw_flush_cache(void)
{
	uint32_t alloc_len = 32 * 1024 * 1024;
	uint32_t *addr = malloc(alloc_len);

	memset(addr, 0, alloc_len);

	free(addr);
}


int main(int argc, char *argv[])
{
	struct ibv_device *ibv_dev = get_device(argv[1]);
	struct ibv_context *ibv_ctx = create_ctx(ibv_dev);
	struct ibv_pd* pd = ibv_alloc_pd(ibv_ctx);
	struct ibv_mr** mrs = create_three_mr(pd, MR_LEN); //sq mr, rq mr, dma dest mr
	struct ibv_cq *rq_cq = create_cq(ibv_ctx);
	struct ibv_cq *sq_cq = create_cq(ibv_ctx);
	struct ibv_qp *qp = create_qp(ibv_ctx, pd, rq_cq, sq_cq);

	int inv_cache = (argc > 2 ? 1 : 0);

	struct timeval start, end, elpase;
	gettimeofday(&start, NULL);

	init_qp(qp);
	qp_self_connected(qp);

	for (uint32_t i = 0; i < 10000; i++) {
		sw_flush_cache();
		normal_traffic(qp, mrs); // RDMA_WRITE: sr_mr[0, MR_LEN} to rq_mr[0, MR_LEN}
		local_dma_copy(qp, mrs); // GGA/DMA   : rq_mr[0, MR_LEN} to dma_dest_mr[0, MR_LEN}
		if (inv_cache) {
			local_cache_invalid(qp, mrs[1], 0); // GGA/MMA w/o writeback: rq_mr[0, MR_LEN}
		} else {
			sleep_nano_seconds(SLEEP_NANO, NULL);
		}
	}

	gettimeofday(&end, NULL);
	timeval_subtract(&elpase, &end, &start);
	printf("%ds:%dusec\n", elpase.tv_sec, elpase.tv_usec);
	return 0;
}
