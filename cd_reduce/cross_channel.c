/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

#include <byteswap.h>
#include <arpa/inet.h>
#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) {return bswap_64(x);}
static inline uint64_t ntohll(uint64_t x) {return bswap_64(x);}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) {return x;}
static inline uint64_t ntohll(uint64_t x) {return x;}
#else
#error __BYTE_ORDER is neither __LITTLEN_ENDIAN nor __BIG_ENDIAN
#endif

extern int sock_connect(const char *servername, int port);
int socket_fd = -1;

int server;
extern int sock_sync_data(int sock, int xfer_size, char *local_data, char *remote_data);

struct ibv_mr *mr;
uint32_t data_chunk[4096];

void create_one_mr(struct ibv_pd *pd)
{
    mr = ibv_reg_mr(pd, data_chunk, sizeof(data_chunk), IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
    if (mr == NULL) {
        printf("failed to reg mr with RR & RW\n");
    }
}

/* structure to exchange data which is needed to connect to QPs */
struct cm_con_data_t {
    uint64_t addr;   /* Buffer address */
    uint32_t rkey;   /* Remote key */
    uint32_t send_qp_num; /* QP number */
    uint32_t recv_qp_num; /* QP number */
    uint16_t lid;    /* LID of the IB port */
    uint8_t gid[16]; /* gid */
}__attribute__((packed));

struct cm_con_data_t local_con_data, remote_con_data;

static void init_local_con_data(struct ibv_context* ctxt, struct ibv_qp *recv_qp, struct ibv_qp *send_qp)
{
    struct ibv_port_attr port_attr = {};
    if (ibv_query_port(ctxt, 1, &port_attr)) {
        printf("failed to port attr\n");
    }

    union ibv_gid local_gid = {};
    if (ibv_query_gid(ctxt, 1, 3, &local_gid)) {
        printf("failed to query gid\n");
    }

    local_con_data.addr = htonll((uintptr_t)data_chunk);
    local_con_data.rkey = htonl(mr->rkey);
    local_con_data.send_qp_num = htonl(send_qp->qp_num);
    local_con_data.recv_qp_num = htonl(recv_qp->qp_num);
    local_con_data.lid = htons(port_attr.lid);
    memcpy(local_con_data.gid, &local_gid, 16);
}

static void get_remote_con_data(void)
{
    struct cm_con_data_t tmp_con_data = {};

    if (sock_sync_data(socket_fd, sizeof(struct cm_con_data_t), (char*)&local_con_data, (char*)&tmp_con_data)) {
        printf("failed to exchange connection data between sides\n");
    }

    remote_con_data.addr = ntohll(tmp_con_data.addr);
    remote_con_data.rkey = ntohl(tmp_con_data.rkey);
    remote_con_data.send_qp_num = ntohl(tmp_con_data.send_qp_num);
    remote_con_data.recv_qp_num = ntohl(tmp_con_data.recv_qp_num);
    remote_con_data.lid = ntohs(tmp_con_data.lid);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);
}

static void sync_fence(void)
{
    uint32_t sync_data = server ? 0x31415926 : 0x27182818;
    uint32_t recv_val = 0;

    if (sock_sync_data(socket_fd, sizeof(sync_data), (char*)&sync_data, (char*)&recv_val)) {
        printf("failed to sync server & client\n");
    }

    if (server && (recv_val != 0x27182818)) {
        printf("server get unexpected val\n");
    }

    if (!server && (recv_val != 0x31415926)) {
        printf("client get unexpected val\n");
    }

    sleep(2);
}

struct ibv_device* get_device(const char*dev_name)
{
    struct ibv_device ** device_list = ibv_get_device_list(NULL);
    struct ibv_device *device;

    for (device = *device_list; device != NULL; device = *(++device_list)) {
        if (strcmp(dev_name, ibv_get_device_name(device)) == 0) {
            break;
        }
    }

    return device;
}

struct mlx5_bf_reg {
   __be32 opmod_idx_opcode;
   __be32 qpn_ds;
};

struct mlx5_wqe_coredirect_seg {
    uint64_t rsvd;
    uint32_t index;
    uint32_t number;
};

void mlx5dv_set_coredirect_seg(struct mlx5_wqe_coredirect_seg *seg, uint32_t index, uint32_t number)
{
    seg->index = htobe32(index);
    seg->number = htobe32(number);
}

static void mlx5dv_set_remote_data_seg(struct mlx5_wqe_raddr_seg *seg, uint64_t addr, uint32_t rkey)
{
    seg->raddr = htobe64(addr);
    seg->rkey = htobe32(rkey);
    seg->reserved = 0;
}

static int ring_qp_connect(struct ibv_qp *qp, int is_remote_recv)
{
    struct ibv_qp_attr attr = {};

    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_1024;
    attr.dest_qp_num = is_remote_recv ? remote_con_data.recv_qp_num : remote_con_data.send_qp_num;
    attr.rq_psn = 0;
    attr.min_rnr_timer = 12;
    attr.max_dest_rd_atomic = 1;
    attr.ah_attr.dlid = remote_con_data.lid;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = 1;

    attr.ah_attr.is_global = 1;
    attr.ah_attr.grh.hop_limit = 1;
    memcpy(&attr.ah_attr.grh.dgid, remote_con_data.gid, 16);
    attr.ah_attr.grh.sgid_index = 3;

    int qp_attr_mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;
    int res = ibv_modify_qp(qp, &attr, qp_attr_mask);
    if (res != 0) {
        printf("failed to modify qp into RTR\n");
    }

    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 10;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;

    qp_attr_mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    res = ibv_modify_qp(qp, &attr, qp_attr_mask);
    if (res != 0) {
        printf("failed to modify qp into RTS\n");
    }

    return res;
}

struct ibv_cq* create_coredirect_cq(struct ibv_context* context, int cqe)
{
    struct ibv_cq_init_attr_ex cq_init_attr_ex = {};
    memset(&cq_init_attr_ex, 0, sizeof(cq_init_attr_ex));

    cq_init_attr_ex.cqe = cqe;
    cq_init_attr_ex.cq_context = NULL;
    cq_init_attr_ex.channel = NULL;
    cq_init_attr_ex.comp_vector = 0;
    cq_init_attr_ex.flags = IBV_CREATE_CQ_ATTR_IGNORE_OVERRUN;
    cq_init_attr_ex.comp_mask = IBV_CQ_INIT_ATTR_MASK_FLAGS;
    struct ibv_cq_ex * cq_ex = ibv_create_cq_ex(context, &cq_init_attr_ex);
    if (cq_ex == NULL) {
        printf("failed to create cq\n");
        return NULL;
    }

    struct ibv_cq *cq = ibv_cq_ex_to_cq(cq_ex);
    return cq;
}

struct ibv_qp* create_coredirect_master_qp(struct ibv_pd* pd, struct ibv_context *context, struct ibv_cq *cq, uint16_t send_wq_size)
{
    struct ibv_qp_attr attr;
    struct ibv_qp *mq;

    struct ibv_qp_init_attr_ex init_attr_ex = {};
    memset(&init_attr_ex, 0, sizeof(init_attr_ex));

    init_attr_ex.send_cq = cq;
    init_attr_ex.recv_cq = cq;

    init_attr_ex.cap.max_send_wr  = send_wq_size;
    init_attr_ex.cap.max_recv_wr  = 0;
    init_attr_ex.cap.max_send_sge = 1;
    init_attr_ex.cap.max_recv_sge = 1;

    init_attr_ex.pd = pd;

    init_attr_ex.qp_type = IBV_QPT_RC;

    init_attr_ex.sq_sig_all = 0;

    init_attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_CREATE_FLAGS;
    init_attr_ex.create_flags = IBV_QP_CREATE_CROSS_CHANNEL;
    mq = ibv_create_qp_ex(context, &init_attr_ex);

    if (mq == NULL) {
        printf("failed to create management qp\n");
    }

    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = 1;
    attr.qp_access_flags = 0;

    int rc = ibv_modify_qp(mq, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS);
    if (rc != 0) {
        printf("failed to modify management qp into init\n");
    }

    union ibv_gid gid;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.path_mtu = IBV_MTU_1024;
    attr.dest_qp_num = mq->qp_num;
    attr.rq_psn = 0;
    attr.max_dest_rd_atomic = 1;
    attr.min_rnr_timer = 12;
    attr.ah_attr.is_global = 1;
    attr.ah_attr.grh.hop_limit = 1;
    attr.ah_attr.grh.sgid_index = 3;
    attr.ah_attr.dlid = 0;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = 1;

    if (ibv_query_gid(context, 1, 3, &gid)) {
        printf("can't read sgid of index %d\n", 3);
    }

    attr.ah_attr.grh.dgid = gid;

    rc = ibv_modify_qp(mq, &attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
                                   IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);

    if (rc != 0) {
        printf("failed to modify management qp into rtr\n");
    }

    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 14;
    attr.retry_cnt = 7;
    attr.rnr_retry = 7;
    attr.sq_psn = 0;
    attr.max_rd_atomic = 1;
    rc = ibv_modify_qp(mq, &attr, IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC);

    if (rc != 0) {
        printf("failed to modify management qp into rts\n");
    }

    return mq;
}

struct ibv_qp* create_coredirect_slave_rc_qp(struct ibv_pd *pd, struct ibv_context *context,
        uint16_t recv_rq_size, struct ibv_cq *cq,
        uint16_t send_wq_size, struct ibv_cq *s_cq)
{
    struct ibv_qp_init_attr_ex init_attr_ex = {};

    init_attr_ex.send_cq = (s_cq == NULL) ? cq : s_cq;
    init_attr_ex.recv_cq = cq;

    init_attr_ex.cap.max_send_wr  = send_wq_size;
    init_attr_ex.cap.max_recv_wr  = recv_rq_size;
    init_attr_ex.cap.max_send_sge = 1;
    init_attr_ex.cap.max_recv_sge = 1;

    init_attr_ex.pd = pd;
    init_attr_ex.qp_type = IBV_QPT_RC;
    init_attr_ex.sq_sig_all = 0;
    init_attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
    init_attr_ex.create_flags = 0;

    init_attr_ex.comp_mask |= IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;
    init_attr_ex.send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM
                    | IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_SEND_WITH_IMM;

    init_attr_ex.create_flags |= IBV_QP_CREATE_MANAGED_SEND;
    init_attr_ex.comp_mask |=  IBV_QP_INIT_ATTR_CREATE_FLAGS;

    init_attr_ex.create_flags |= IBV_QP_CREATE_MANAGED_RECV;
    init_attr_ex.comp_mask |=  IBV_QP_INIT_ATTR_CREATE_FLAGS;

    struct ibv_qp *qp = ibv_create_qp_ex(context, &init_attr_ex);
    if (qp == NULL) {
        printf("failed to create slave qp\n");
        return NULL;
    }

    struct ibv_qp_attr qp_attr = {};
    qp_attr.qp_state = IBV_QPS_INIT;
    qp_attr.pkey_index = 0;
    qp_attr.port_num = 1;
    qp_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE;

    if (ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
        printf("failed to modify slave qp into init\n");
    }

    return qp;
}

struct sq_cq_ctx {
    uint32_t cmpl_cnt;

    struct mlx5dv_cq *cq;
    size_t cqes;
};

void init_sq_cq_ctx(struct sq_cq_ctx* cq_ctx, struct ibv_cq *cq, size_t num_of_cqes) {
    cq_ctx->cmpl_cnt = 0;
    cq_ctx->cqes = num_of_cqes;

    struct mlx5dv_obj dv_obj = {};

    cq_ctx->cq = (struct mlx5dv_cq *)malloc(sizeof(struct mlx5dv_cq));
    dv_obj.cq.in = cq;
    dv_obj.cq.out = cq_ctx->cq;

    mlx5dv_init_obj(&dv_obj, MLX5DV_OBJ_CQ);
}

struct qp_ctx {
    struct mlx5dv_qp *qp;
    struct mlx5dv_cq *cq;

    uint32_t qpn;

    uint32_t write_cnt;
    uint32_t cmpl_cnt;

    uint32_t poll_cnt;

    int offset;

    uint32_t number_of_duplicates;
    uint32_t current_wqe_index_to_exec;

    struct mlx5_bf_reg bf_reg;

    // The number of WQEs that are expected to be executed
    // during a single collective operation
    size_t wqes;

    // The number of CQEs that are expected to be generated during a single
    // collective operation
    size_t cqes;

     // A pointer to the index location of the current expected CQE in the CQ.
     // The location of the current expected CQE is the location of the CQE that
     // is expected to be generated by the hardware after the QP completed all
     // the WQEs of a single collective operation.
     // After each collective operation is done, this pointer is updated to point
     // to the next expected CQE that one should wait for, when waiting for a
     // the next collective operation to be finished.
     volatile struct mlx5_cqe64 *cur_cqe;

     struct qp_ctx* peer;

    int has_scq;
    struct sq_cq_ctx *scq;
};

struct qp_ctx* wrap_qp_into_qp_ctx(struct ibv_qp *qp, struct ibv_cq *cq, size_t num_of_wqes,
        size_t num_of_cqes, int has_scq, struct ibv_cq *scq, size_t num_of_send_cqes)
{
    struct qp_ctx* ctx = calloc(1, sizeof(struct qp_ctx));

    struct mlx5dv_obj dv_obj = {};

    ctx->qp = (struct mlx5dv_qp *)calloc(1, sizeof(struct mlx5dv_qp));
    ctx->cq = (struct mlx5dv_cq *)calloc(1, sizeof(struct mlx5dv_cq));
    ctx->qpn = qp->qp_num;

    dv_obj.qp.in = qp;
    dv_obj.qp.out = ctx->qp;
    dv_obj.cq.in = cq;
    dv_obj.cq.out = ctx->cq;

    mlx5dv_init_obj(&dv_obj, MLX5DV_OBJ_QP | MLX5DV_OBJ_CQ);
    ctx->bf_reg.qpn_ds = htobe32(ctx->qpn << 8);

    ctx->current_wqe_index_to_exec = 0;
    ctx->scq = NULL;

    if (num_of_wqes > ctx->qp->sq.wqe_cnt) {
        printf("ERROR - SQ size is not big enough to hold all wqes\n");
    }

    int rounded_num_of_wqes = num_of_wqes;
    while (rounded_num_of_wqes && ctx->qp->sq.wqe_cnt % rounded_num_of_wqes) {
        ++rounded_num_of_wqes;
    }
    ctx->write_cnt = 0;
    ctx->wqes = rounded_num_of_wqes;
    ctx->number_of_duplicates = rounded_num_of_wqes ? ctx->qp->sq.wqe_cnt / rounded_num_of_wqes : 0;
    ctx->offset = (ctx->qp->sq.stride * rounded_num_of_wqes) / sizeof(uint32_t);

    ctx->cqes = num_of_cqes;
    ctx->cmpl_cnt = 0;
    ctx->poll_cnt = num_of_cqes > 0 ? num_of_cqes - 1 : 0;
    volatile void *tar = (volatile void *)((volatile char*)ctx->cq->buf +
                                           ((ctx->poll_cnt) & (ctx->cq->cqe_cnt - 1)) * ctx->cq->cqe_size);
    ctx->cur_cqe = (volatile struct mlx5_cqe64 *)tar;

    ctx->has_scq = has_scq;
    if (has_scq) {
        ctx->scq = calloc(1, sizeof(struct sq_cq_ctx));
        init_sq_cq_ctx(ctx->scq, scq, num_of_send_cqes);
    } else {
        ctx->scq = NULL;
    }

    ctx->peer = ctx;

    return ctx;
}

void update_qp_ctx_peer(struct qp_ctx* self, struct qp_ctx* peer)
{
    self->peer = peer;
}

void rdma_write_with_imm_need_complete(struct qp_ctx *slave_qp_ctx)
{
    struct mlx5_wqe_ctrl_seg *ctrl;
    struct mlx5_wqe_raddr_seg *rseg;
    struct mlx5_wqe_data_seg *dseg;

    const uint8_t ds = 3;
    int wqe_count = slave_qp_ctx->qp->sq.wqe_cnt;
    ctrl = (struct mlx5_wqe_ctrl_seg *)((char *)slave_qp_ctx->qp->sq.buf + slave_qp_ctx->qp->sq.stride * (slave_qp_ctx->write_cnt % wqe_count));
    uint8_t fm_ce_se = 0x8; // need generate CQE
    slave_qp_ctx->scq->cmpl_cnt++;
    mlx5dv_set_ctrl_seg(ctrl, slave_qp_ctx->write_cnt, MLX5_OPCODE_RDMA_WRITE_IMM, 0, slave_qp_ctx->qpn, fm_ce_se, ds, 0, 0xdeadbeef);
    slave_qp_ctx->peer->cmpl_cnt++;

    rseg = (struct mlx5_wqe_raddr_seg *)(ctrl + 1);
    mlx5dv_set_remote_data_seg(rseg, remote_con_data.addr, remote_con_data.rkey);

    dseg = (struct mlx5_wqe_data_seg *)(rseg + 1);
    mlx5dv_set_data_seg(dseg, 16, mr->lkey, (uint64_t)data_chunk);

    slave_qp_ctx->write_cnt++;
}

void rdma_send_with_imm_no_need_complete(struct qp_ctx *slave_qp_ctx)
{
    struct mlx5_wqe_ctrl_seg *ctrl;
    struct mlx5_wqe_data_seg *dseg;

    const uint8_t ds = 1;
    int wqe_count = slave_qp_ctx->qp->sq.wqe_cnt;
    ctrl = (struct mlx5_wqe_ctrl_seg *)((char *)slave_qp_ctx->qp->sq.buf + slave_qp_ctx->qp->sq.stride * (slave_qp_ctx->write_cnt % wqe_count));
    mlx5dv_set_ctrl_seg(ctrl, slave_qp_ctx->write_cnt, MLX5_OPCODE_SEND_IMM, 0, slave_qp_ctx->qpn, 0, ds, 0, 0xcafebeef);
    slave_qp_ctx->peer->cmpl_cnt++;

    slave_qp_ctx->write_cnt++;
}

void core_direct_recv_enable(struct qp_ctx *mqp_ctx, struct qp_ctx *slave_qp_ctx)
{
    struct mlx5_wqe_ctrl_seg *ctrl = NULL;
    struct mlx5_wqe_coredirect_seg *wseg = NULL;

    const uint8_t ds = 2;
    int wqe_count = mqp_ctx->qp->sq.wqe_cnt;

    ctrl = (struct mlx5_wqe_ctrl_seg *)((char *)mqp_ctx->qp->sq.buf + mqp_ctx->qp->sq.stride * (mqp_ctx->write_cnt % wqe_count));
    mlx5dv_set_ctrl_seg(ctrl, mqp_ctx->write_cnt, 0x16, 0x00, mqp_ctx->qpn, 0 /*CE*/, ds, 0, 0);

    wseg = (struct mlx5_wqe_coredirect_seg *)(ctrl + 1);
    mlx5dv_set_coredirect_seg(wseg, 0x6fff, slave_qp_ctx->qpn);
    mqp_ctx->write_cnt += 1;
}

void core_direct_send_enable(struct qp_ctx *mqp_ctx, struct qp_ctx *slave_qp_ctx)
{
    struct mlx5_wqe_ctrl_seg *ctrl = NULL;
    struct mlx5_wqe_coredirect_seg *wseg = NULL;

    const uint8_t ds = 2;
    int wqe_count = mqp_ctx->qp->sq.wqe_cnt;

    ctrl = (struct mlx5_wqe_ctrl_seg *)((char *)mqp_ctx->qp->sq.buf + mqp_ctx->qp->sq.stride * (mqp_ctx->write_cnt % wqe_count));
    mlx5dv_set_ctrl_seg(ctrl, mqp_ctx->write_cnt, 0x17, 0x00, mqp_ctx->qpn, 0 /*CE*/, ds, 0, 0);

    wseg = (struct mlx5_wqe_coredirect_seg *)(ctrl + 1);
    mlx5dv_set_coredirect_seg(wseg, slave_qp_ctx->write_cnt, slave_qp_ctx->qpn);
    mqp_ctx->write_cnt += 1;
}

void core_direct_wait_on_rcq(struct qp_ctx *mqp_ctx, struct qp_ctx *slave_qp_ctx)
{
    struct mlx5_wqe_ctrl_seg *ctrl = NULL;
    struct mlx5_wqe_coredirect_seg *wseg = NULL;

    const uint8_t ds = 2;
    int wqe_count = mqp_ctx->qp->sq.wqe_cnt;

    ctrl = (struct mlx5_wqe_ctrl_seg *)((char *)mqp_ctx->qp->sq.buf + mqp_ctx->qp->sq.stride * (mqp_ctx->write_cnt % wqe_count));
    mlx5dv_set_ctrl_seg(ctrl, mqp_ctx->write_cnt, 0x0f, 0, mqp_ctx->qpn, 0 /* CE */, ds, 0, 0);

    wseg = (struct mlx5_wqe_coredirect_seg *)(ctrl + 1);
    uint32_t index = slave_qp_ctx->cmpl_cnt - 1;
    uint32_t number = slave_qp_ctx->cq->cqn;
    mlx5dv_set_coredirect_seg(wseg, index, number);

    mqp_ctx->write_cnt += 1;
}

void fill_wqe_nop(struct qp_ctx *ctx, int pad_wqes)
{
    struct mlx5_wqe_ctrl_seg *ctrl;
    const uint8_t ds = (pad_wqes * (ctx->qp->sq.stride / 16));

    int wqe_count = ctx->qp->sq.wqe_cnt;
    ctrl = (struct mlx5_wqe_ctrl_seg *)((char *)ctx->qp->sq.buf + ctx->qp->sq.stride * (ctx->write_cnt % wqe_count));
    mlx5dv_set_ctrl_seg(ctrl, ctx->write_cnt, 0x00, 0, ctx->qpn, 0, ds, 0, 0);

    ctx->write_cnt += pad_wqes;
}

void qp_ctx_finish(struct qp_ctx *ctx)
{
    int pad_wqes = 8;
    int target_count = ctx->wqes;

    while (ctx->write_cnt + pad_wqes < target_count) {
        fill_wqe_nop(ctx, pad_wqes);
    }

    if (ctx->write_cnt < target_count) {
        fill_wqe_nop(ctx, target_count - ctx->write_cnt);
    }
}

void cross_channel_cd_ring_db(struct qp_ctx *mqp_ctx)
{
    mqp_ctx->current_wqe_index_to_exec = mqp_ctx->wqes;

    mqp_ctx->bf_reg.opmod_idx_opcode = htobe32(mqp_ctx->current_wqe_index_to_exec << 8);
    asm volatile("" ::: "memory");

    mqp_ctx->qp->dbrec[1] = htobe32(mqp_ctx->current_wqe_index_to_exec);
    asm volatile("sfence" ::: "memory");

    *(uint64_t*)mqp_ctx->qp->bf.reg = *(uint64_t*)&(mqp_ctx->bf_reg);
    asm volatile("sfence" ::: "memory");
}

int main(int argc, char *argv[])
{
    char *dev_name = strdup(argv[1]);

    struct ibv_device *dev = get_device(dev_name);
    struct ibv_context *ctxt = ibv_open_device(dev);
    struct ibv_pd *pd = ibv_alloc_pd(ctxt);
    struct ibv_cq *cq = ibv_create_cq(ctxt, 16, NULL, NULL, 0);

    create_one_mr(pd);

    struct ibv_cq *mcq = create_coredirect_cq(ctxt, 0 + 1); // actual zero, create cq with 1 CQE for general program
    struct ibv_qp *mqp = create_coredirect_master_qp(pd, ctxt, mcq, 6 + 2); // no RQ
                                                                            // SQ with 8WQE:
                                                                            // recv_enable: recv_qp, recv_enable: send_qp
                                                                            // send_enable: send_qp
                                                                            // wait_cq: recv_qp
                                                                            // send_enable: recv_qp
                                                                            // wait_cq: send_qp
    struct qp_ctx *mqp_ctx = wrap_qp_into_qp_ctx(mqp, mcq, 6 + 2, 0, 0, NULL, 0); // 8 WQE, 0 cqe, no scq

    struct ibv_cq *send_qp_rcq = create_coredirect_cq(ctxt, 1);
    struct ibv_cq *send_qp_scq = create_coredirect_cq(ctxt, 1);
    struct ibv_qp *send_qp = create_coredirect_slave_rc_qp(pd, ctxt, 1, send_qp_rcq, 1, send_qp_scq); //RQ:1WQE, SQ: 1WQE
    struct qp_ctx *sq_ctx = wrap_qp_into_qp_ctx(send_qp, send_qp_rcq, 1, 1, 1, send_qp_scq, 1); // 1 WQE, 1 CQE, scq with 1 CQE

    struct ibv_cq *recv_qp_rcq = create_coredirect_cq(ctxt, 1);
    struct ibv_cq *recv_qp_scq = create_coredirect_cq(ctxt, 0 + 1);
    struct ibv_qp *recv_qp = create_coredirect_slave_rc_qp(pd, ctxt, 1, recv_qp_rcq, 1, recv_qp_scq); //RQ: 1WQE, SQ:1WQE
    struct qp_ctx *rq_ctx = wrap_qp_into_qp_ctx(recv_qp, recv_qp_rcq, 1, 1, 1, recv_qp_scq, 0); // 1 WQE, 1 CQE, scq with 0 CQE

    if (argc == 3) {
        server = 0;
        socket_fd = sock_connect(argv[2], 8976);
        printf("client: socket_fd = %d\n", socket_fd);
    } else {
        server = 1;
        socket_fd = sock_connect(NULL, 8976);
        printf("server: socket_fd = %d\n", socket_fd);
    }

    init_local_con_data(ctxt, recv_qp, send_qp);

    get_remote_con_data();
    printf("mqpn:0x%06x\n"
           "local_send_qpn:0x%06x, remote_recv_qpn:0x%06x\n"
           "local_recv_qpn:0x%06x, remote_send_qpn:0x%06x\n"
           "local data:%p, local lkey:0x%08x local rkey:0x%08x\n"
           "remote data:%p, remote rkey:0x%08x\n", mqp_ctx->qpn,
            sq_ctx->qpn, remote_con_data.recv_qp_num,
            rq_ctx->qpn, remote_con_data.send_qp_num,
            data_chunk, mr->lkey, mr->rkey,
            (void*)(remote_con_data.addr), remote_con_data.rkey);

    ring_qp_connect(recv_qp, 0);
    ring_qp_connect(send_qp, 1);
    update_qp_ctx_peer(rq_ctx, sq_ctx);
    update_qp_ctx_peer(sq_ctx, rq_ctx);

    core_direct_recv_enable(mqp_ctx, rq_ctx);
    core_direct_recv_enable(mqp_ctx, sq_ctx);

    rdma_write_with_imm_need_complete(sq_ctx);
    core_direct_send_enable(mqp_ctx, sq_ctx);
    core_direct_wait_on_rcq(mqp_ctx, rq_ctx);

    rdma_send_with_imm_no_need_complete(rq_ctx);
    core_direct_send_enable(mqp_ctx, rq_ctx);
    core_direct_wait_on_rcq(mqp_ctx, sq_ctx);

    qp_ctx_finish(mqp_ctx);
    cross_channel_cd_ring_db(mqp_ctx);

    sync_fence(); // align that remote receive is ready

    printf("mqp->wqes = %d, write_cnt:%d \n", mqp_ctx->wqes, mqp_ctx->write_cnt);
    printf("send_mqp->wqes = %d, write_cnt:%d \n", sq_ctx->wqes, sq_ctx->write_cnt);
    printf("rqp->wqes = %d, write_cnt:%d \n", rq_ctx->wqes, rq_ctx->write_cnt);

    printf("=============================================");
    struct ibv_wc wc = {};
    printf("start checking send qp scq\n");
    while (ibv_poll_cq(send_qp_scq, 1, &wc) != 0) break;
    if (wc.status != 0 || wc.opcode != IBV_WC_RDMA_WRITE) {
        printf("send qp scq 1st get unexpected CQE\n");
    } else {
        printf("send qp scq 1st get expected CQE\n");
    }

    printf("=============================================");
    printf("start checking recv qp rcq\n");
    while (ibv_poll_cq(recv_qp_rcq, 1, &wc) != 0) break;
    if (wc.status != 0 || wc.imm_data != 0xdeadbeef) {
        printf("recv qp rcq 1st get unexpected CQE\n");
    } else {
        printf("recv qp rcq 1st get expected CQE\n");
    }

    printf("=============================================");
    memset(&wc, 0, sizeof(wc));
    printf("start checking send qp rcq\n");
    while (ibv_poll_cq(send_qp_rcq, 1, &wc) != 0) break;
    if (wc.status != 0 || wc.imm_data != 0xcafebeef) {
        printf("send qp rcq 1st get unexpected CQE\n");
    } else {
        printf("send qp rcq 1st get expected CQE\n");
    }
    printf("=============================================\n");

    sync_fence();

    if (ibv_destroy_qp(recv_qp) != 0) {
        printf("failed to destroy recv_qp:0x%06x\n", recv_qp->qp_num);
    }

    if (ibv_destroy_qp(send_qp) != 0) {
        printf("failed to destroy send_qp:0x%06x\n", send_qp->qp_num);
    }

    if (ibv_destroy_qp(mqp) != 0) {
        printf("failed to destroy mqp:0x%06x\n", mqp->qp_num);
    }

    return 0;
}
