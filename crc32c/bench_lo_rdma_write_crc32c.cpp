/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

/* Run environment:
 *  $ show_gids | grep mlx5_0 | grep v2 | grep '\<3\>'
 *    DEV     PORT  INDEX  GID                                     IPv4            VER   DEV
 *    ---     ----  -----  ---                                     ------------    ---   ---
 *    mlx5_0  1      3     0000:0000:0000:0000:0000:ffff:c0a8:210f 192.168.33.15   v2    enp6s0f0np0
 *
 * Build:
 * $ gcc -o rdma_read_crc rdma_read_crc32c.c -libverbs -lmlx5
 *
 * Run:
 * $ ./rdma_read_crc mlx5_0
 *
 * Use python to verify:
 * || $ python3.12
 * || >>> import crc32c
 * || >>> print(hex(crc32c.crc32c(b"a" * 4096)))
 * || 0x26c74ca2
 */

#include <sys/time.h>
#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

#include <benchmark/benchmark.h>

#define info(format, arg...) fprintf(stdout, format, ##arg)
#define err(format, arg...) fprintf(stderr, "ERROR: " format, ##arg)

/* structure of system resources */
struct resources {
    struct ibv_context *ib_ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;

    struct ibv_mr *src_data_mr; /* MR for src data buffer */
    struct ibv_mr *dst_data_mr; /* MR for data buffer */
    struct ibv_mr *pi_mr[MAX_CRC_TASK_SIZE];       /* MR for protection information buffer */

    struct mlx5dv_mkey *sig_mkey[MAX_CRC_TASK_SIZE];
};

static const char *wc_opcode_str(enum ibv_wc_opcode opcode)
{
    const char *str;

    switch (opcode) {
    case IBV_WC_RDMA_WRITE:
        str = "RDMA_WRITE";
        break;
    case IBV_WC_RDMA_READ:
        str = "RDMA_READ";
        break;
    case IBV_WC_LOCAL_INV:
        str = "LOCAL_INV";
        break;
    case IBV_WC_DRIVER1:
        str = "DRIVER1";
        break;
    case IBV_WC_DRIVER3:
        str = "DRIVER3";
        break;
    default:
        str = "UNKNOWN";
    };

    return str;
}

static int poll_completion(struct ibv_cq *cq, enum ibv_wc_opcode expected)
{
    unsigned long start_time_msec;
    unsigned long cur_time_msec;
    struct timeval cur_time;
    struct ibv_wc wc = {};
    int poll_result;

    /* poll the completion for a while before giving up of doing it .. */
    gettimeofday(&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    do {
        poll_result = ibv_poll_cq(cq, 1, &wc);
        gettimeofday(&cur_time, NULL);
        cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    } while ((poll_result == 0) && ((cur_time_msec - start_time_msec) < 2000)); // poll CQ timeout 2s

    if (poll_result < 0) {
        err("poll CQ failed\n");
        return -1;
    }
    if (poll_result == 0) {
        err("poll CQ timeout\n");
        return -1;
    }
    if (wc.status != IBV_WC_SUCCESS) {
        err("CQE status %s, opcode %s\n", ibv_wc_status_str(wc.status),
            wc_opcode_str(wc.opcode));
        return -1;
    }
    if (wc.opcode != expected) {
        err("CQE opcode (%s:%d) != expected opcode (%s)\n",
            wc_opcode_str(wc.opcode), wc.opcode, wc_opcode_str(expected));
        return -1;
    }
#if 0
    info("CQE status %s, opcode %s:%d\n", ibv_wc_status_str(wc.status),
         wc_opcode_str(wc.opcode), wc.opcode);
#endif

    return 0;
}

static struct mlx5dv_mkey *create_sig_mkey(struct ibv_pd *pd)
{
    struct mlx5dv_mkey_init_attr mkey_attr = {};
    mkey_attr.pd = pd;
    mkey_attr.max_entries = 4;
    mkey_attr.create_flags = MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT | MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE;
    struct mlx5dv_mkey *mkey;

    mkey = mlx5dv_create_mkey(&mkey_attr);
    if (!mkey)
        err("mlx5dv_create_mkey: %s\n", strerror(errno));

    return mkey;
}

static int destroy_sig_mkey(struct mlx5dv_mkey **mkey)
{
    int rc;

    if (!*mkey)
        return 0;

    rc = mlx5dv_destroy_mkey(*mkey);
    if (rc) {
        err("mlx5dv_destroy_mkey: %s\n", strerror(rc));
        return -1;
    }
    *mkey = NULL;

    return 0;
}

static
int configure_mkey_layout(struct resources *res, int src_idx)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
    struct mlx5dv_qp_ex *dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
    struct mlx5dv_mkey *mkey = res->sig_mkey[src_idx];

    /* !!! Do not use IBV_ACCESS_RELAXED_ORDERING */
    uint32_t access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE;

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_INLINE;

    struct mlx5dv_mr_interleaved mr_interleaved[2];
    /* data */
    mr_interleaved[0].addr = (uintptr_t)res->dst_data_mr->addr;
    mr_interleaved[0].bytes_count = 4096;
    mr_interleaved[0].bytes_skip = 0;
    mr_interleaved[0].lkey = res->dst_data_mr->lkey;
    /* protection */
    mr_interleaved[1].addr = (uintptr_t)res->pi_mr[src_idx]->addr;
    mr_interleaved[1].bytes_count = sizeof(uint32_t); // 4 bytes for crc32c result
    mr_interleaved[1].bytes_skip = 0;
    mr_interleaved[1].lkey = res->pi_mr[src_idx]->lkey;

    mlx5dv_wr_mr_interleaved(dv_qp, mkey, access_flags, 1, 2, mr_interleaved);

    return ibv_wr_complete(qpx);
}

static
int configure_sig_mkey(struct resources *res, int src_idx, struct mlx5dv_sig_block_attr *sig_attr)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
    struct mlx5dv_qp_ex *dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
    struct mlx5dv_mkey *mkey = res->sig_mkey[src_idx];
    struct mlx5dv_mkey_conf_attr conf_attr = {};

    if (configure_mkey_layout(res, src_idx)) {
        err("failed to configure mkey layout\n");
        return -1;
    }

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;

    mlx5dv_wr_mkey_configure(dv_qp, mkey, 1, &conf_attr);
    mlx5dv_wr_set_mkey_sig_block(dv_qp, sig_attr);

    if (ibv_wr_complete(qpx)) {
        err("failed to set mkey sig block\n");
        return -1;
    }
    return 0;
}

enum sig_mode {
    SIG_MODE_INSERT_ON_MEM,
};

static int reg_sig_mkey(struct resources *res, int src_idx, enum sig_mode mode)
{
    struct mlx5dv_sig_crc crc_sig;
    struct mlx5dv_sig_block_domain mem_domain;

    switch (mode) {
    case SIG_MODE_INSERT_ON_MEM:
        memset(&crc_sig, 0, sizeof(crc_sig));
        crc_sig.type = MLX5DV_SIG_CRC_TYPE_CRC32C;
        crc_sig.seed = 0x0;

        memset(&mem_domain, 0, sizeof(mem_domain));
        mem_domain.sig_type = MLX5DV_SIG_TYPE_CRC;
        mem_domain.block_size = MLX5DV_BLOCK_SIZE_4096;
        mem_domain.sig.crc = &crc_sig;
        break;
    default:
        break;
    }

    struct mlx5dv_sig_block_attr sig_attr = {
        .mem = &mem_domain,
        .check_mask = MLX5DV_SIG_MASK_CRC32C,
    };

    if (configure_sig_mkey(res, src_idx, &sig_attr))
        return -1;

    //info("Post mkey configure WR, opcode DRIVER1\n");

    if (poll_completion(res->qp->send_cq, IBV_WC_DRIVER1)) {
        err("Failed to configure sig MKEY\n");
        return -1;
    }
    //info("Sig MKEY is configured\n");

    return 0;
}

static int check_sig_mkey(struct mlx5dv_mkey *mkey)
{
    struct mlx5dv_mkey_err err_info;
    const char *sig_err_str = "";
    int sig_err;
    int rc;

    rc = mlx5dv_mkey_check(mkey, &err_info);
    if (rc) {
        err("mlx5dv_mkey_check: %s\n", strerror(rc));
        return -1;
    }

    sig_err = err_info.err_type;
    switch (sig_err) {
    case MLX5DV_MKEY_NO_ERR:
        break;
    default:
        err("unknown sig error %d\n", sig_err);
        break;
    }

    if (sig_err)
        err("SIG ERROR: %s: expected 0x%lx, actual 0x%lx, offset %lu\n",
             sig_err_str, err_info.err.sig.expected_value,
             err_info.err.sig.actual_value, err_info.err.sig.offset);

    return sig_err;
}

static int destroy_cq(struct ibv_cq **cq)
{
    int rc;

    if (!*cq)
        return 0;

    rc = ibv_destroy_cq(*cq);
    if (rc) {
        err("ibv_destroy_cq: %s\n", strerror(rc));
        rc = -1;
    }
    *cq = NULL;

    return rc;
}

static struct ibv_qp *create_qp(struct ibv_context *ctxt, struct ibv_pd* pd, struct ibv_cq *rq_cq, struct ibv_cq *sq_cq)
{
    struct ibv_qp *qp;

    struct ibv_qp_cap qp_cap = {
        .max_send_wr = 2 + MAX_CRC_TASK_SIZE,
        .max_send_sge = 1,
        .max_inline_data = 64 * 2,
    };

    struct ibv_qp_init_attr_ex qp_attr = {
        .qp_context = NULL,
        .send_cq = sq_cq,
        .recv_cq = rq_cq,
        .cap = qp_cap,

        .qp_type = IBV_QPT_RC,
        .sq_sig_all = 0,
        .comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
        .pd = pd,
        .send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_LOCAL_INV,
    };

    /* signature specific attributes */
    struct mlx5dv_qp_init_attr qp_dv_attr = {
        .comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS,
        .send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
    };

    qp = mlx5dv_create_qp(ctxt, &qp_attr, &qp_dv_attr);
    if (!qp)
        err("mlx5dv_create_qp: %s\n", strerror(errno));

    return qp;
}

static int free_mr(struct ibv_mr **mr)
{
    void *ptr;
    int rc;

    if (!*mr)
        return 0;

    ptr = (*mr)->addr;
    rc = ibv_dereg_mr(*mr);
    if (rc)
        err("ibv_dereg_mr: %s\n", strerror(rc));

    *mr = NULL;
    free(ptr);

    return rc;
}

struct ibv_mr * alloc_mr(struct ibv_pd *pd, size_t size)
{
    int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_RELAXED_ORDERING;

    void *ptr = malloc(size);
    if (!ptr) {
        err("calloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(ptr, 'a', size); // data payload is filled with b'a'

    struct ibv_mr *mr = ibv_reg_mr(pd, ptr, size, mr_flags);
    if (!mr) {
        err("ibv_reg_mr: %s\n", strerror(errno));
        free(ptr);
        return NULL;
    }

    return mr;
}

static int resources_destroy(struct resources *res)
{
    int rc = 0;

    ibv_destroy_qp(res->qp);

    for (int i = 0; i < MAX_CRC_TASK_SIZE; ++i)
        if (destroy_sig_mkey(&res->sig_mkey[i])) rc = -1;

    for (int i = 0; i < MAX_CRC_TASK_SIZE; ++i)
        if (free_mr(&res->pi_mr[i])) rc = -1;

    if (free_mr(&res->src_data_mr)) rc = -1;

    if (free_mr(&res->dst_data_mr)) rc = -1;

    if (destroy_cq(&res->cq)) rc = -1;

    ibv_dealloc_pd(res->pd);
    res->ib_ctx = NULL;

    return rc;
}

struct ibv_context* get_dev_ctx(const char*dev_name)
{
    int32_t dev_cnt = 0;
    struct ibv_device ** device_list = ibv_get_device_list(&dev_cnt);
    struct ibv_device *device = NULL;;

    if (device_list == NULL) {
        return NULL;
    }

    for (uint32_t idx = 0; idx < dev_cnt; idx++) {
        device = device_list[idx];
        if (strcmp(dev_name, ibv_get_device_name(device)) == 0) {
            break;
        }
    }

    if (device == NULL) {
        return NULL;
    }

    /* must open device with DEVX */
    struct mlx5dv_context_attr attr = {.flags = MLX5DV_CONTEXT_FLAGS_DEVX};
    struct ibv_context *ctxt = mlx5dv_open_device(device, &attr);

    ibv_free_device_list(device_list);

    return ctxt;
}

void check_support_crc32c(struct ibv_context *ctxt)
{
    struct mlx5dv_context dv_ctx = {};
    dv_ctx.comp_mask = MLX5DV_CONTEXT_MASK_SIGNATURE_OFFLOAD;

    if (!mlx5dv_is_supported(ctxt->device)) {
        printf("device %s doesn't support DV\n", ibv_get_device_name(ctxt->device));
        exit(-1);
    }

    if (mlx5dv_query_device(ctxt, &dv_ctx) != 0 || !(dv_ctx.comp_mask & MLX5DV_CONTEXT_MASK_SIGNATURE_OFFLOAD)) {
        printf("%s does not support signature offload\n", ibv_get_device_name(ctxt->device));
        exit(-1);
    }

    if (!(dv_ctx.sig_caps.crc_type & MLX5DV_SIG_CRC_TYPE_CAP_CRC32C)) {
        printf("%s signature CRC32C offload isn't supported\n", ibv_get_device_name(ctxt->device));
    }
}

uint32_t init_qp(struct ibv_qp *qp)
{
    int mask = IBV_QP_STATE | IBV_QP_PORT | IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS;
    struct ibv_qp_attr attr = {
        .qp_state = IBV_QPS_INIT,
        .qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE,
        .pkey_index = 0,
        .port_num = 1,
    };

    if (ibv_modify_qp(qp, &attr, mask)) {
        printf("failed to modify qp:0x%x to init\n", qp->qp_num);
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

uint32_t get_port_attr(struct ibv_context *ibv_ctx, struct ibv_port_attr *port_attr, uint8_t port_num)
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


uint32_t query_gid_lid(struct ibv_context *ibv_ctx, union ibv_gid *gid, uint16_t *lid)
{
    struct ibv_port_attr port_attr = {};

    if (get_port_attr(ibv_ctx, &port_attr, 1)) {
        printf("failed to query port attr\n");
        exit(__LINE__);
    }
    *lid = port_attr.lid;

    if (ibv_query_gid(ibv_ctx, 1, 1, gid)) {
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

    int mask = IBV_QP_STATE | IBV_QP_AV | \
        IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | \
        IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    struct ibv_qp_attr qpa = {
        .qp_state = IBV_QPS_RTR,
        .path_mtu = IBV_MTU_4096,
        .rq_psn = 0,
        .dest_qp_num = qp->qp_num,
        .ah_attr = {
            .grh = {
                .dgid = gid,
                .sgid_index = 1,
                .hop_limit = 64
            },
            .is_global = 1,
            .port_num = 1
        },
        .max_dest_rd_atomic = 0,
        .min_rnr_timer = 0x12
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
    qpa.max_rd_atomic  = 0;
    mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |\
        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    if (ibv_modify_qp(qp, &qpa, mask)) {
        printf("failed to modify qp:0x%x to rts, errno 0x%x\n", qp->qp_num, errno);
        exit(__LINE__);
    }
    return 0;
}

#define BATCH 100000
struct resources res;
static void BM_Crc32cFixedBuf(benchmark::State& state)  // NOLINT(runtime/references)
{
    while (state.KeepRunningBatch(BATCH)) {
        for (int i = 0; i < BATCH; ++i) {
            struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res.qp);

            ibv_wr_start(qpx);
            switch (MAX_CRC_TASK_SIZE) {
            case 16: qpx->wr_id = 16; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[15]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case 15: qpx->wr_id = 15; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[14]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case 14: qpx->wr_id = 14; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[13]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case 13: qpx->wr_id = 13; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[12]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case 12: qpx->wr_id = 12; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[11]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case 11: qpx->wr_id = 11; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[10]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case 10: qpx->wr_id = 10; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[9]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  9: qpx->wr_id =  9; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[8]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  8: qpx->wr_id =  8; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[7]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  7: qpx->wr_id =  7; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[6]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  6: qpx->wr_id =  6; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[5]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  5: qpx->wr_id =  5; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[4]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  4: qpx->wr_id =  4; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[3]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  3: qpx->wr_id =  3; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[2]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  2: qpx->wr_id =  2; qpx->wr_flags = 0;
                ibv_wr_rdma_write(qpx, res.sig_mkey[1]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            case  1: qpx->wr_id =  1; qpx->wr_flags = IBV_SEND_SIGNALED;
                ibv_wr_rdma_write(qpx, res.sig_mkey[0]->rkey, 0);
                ibv_wr_set_sge(qpx, res.src_data_mr->lkey, (uintptr_t)res.src_data_mr->addr, 4096);
            }

            if (ibv_wr_complete(qpx))
                err("failed to post RDMA_WRITE WRs\n");

            if (poll_completion(res.qp->send_cq, IBV_WC_RDMA_WRITE))
                err("failed to complete RDMA_WRITE operaion\n");
        }
    }

    state.SetItemsProcessed(state.iterations());

    for (int i = 0; i < MAX_CRC_TASK_SIZE; i++) {
        if (check_sig_mkey(res.sig_mkey[i]) < 0) {
            err("failed to check sig_mkey\n");
        }
    }

    info("CRC32C = 0X%08X, 0X%08X\n", *(uint32_t *)res.pi_mr[0]->addr ^ 0XFFFFFFFF, *(uint32_t *)res.pi_mr[MAX_CRC_TASK_SIZE - 1]->addr ^ 0XFFFFFFFF);
}

BENCHMARK(BM_Crc32cFixedBuf);

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);

    char *dev_name = strdup(argv[1]);
    res.ib_ctx = get_dev_ctx(dev_name);
    check_support_crc32c(res.ib_ctx);

    res.pd = ibv_alloc_pd(res.ib_ctx);
    res.cq = ibv_create_cq(res.ib_ctx, 16, NULL, NULL, 0);
    res.src_data_mr = alloc_mr(res.pd, 4096);
    res.dst_data_mr = alloc_mr(res.pd, 4096);

    for (int i = 0; i < MAX_CRC_TASK_SIZE; i++) {
        res.pi_mr[i] = alloc_mr(res.pd, 4);
        res.sig_mkey[i] = create_sig_mkey(res.pd);
    }

    res.qp = create_qp(res.ib_ctx, res.pd, res.cq, res.cq);

    init_qp(res.qp);
    qp_self_connected(res.qp);

    for (int i = 0; i < MAX_CRC_TASK_SIZE; i++) {
        reg_sig_mkey(&res, i, SIG_MODE_INSERT_ON_MEM);
    }

    printf("\n========= CRC32C task size: 0x%x =========\n\n", MAX_CRC_TASK_SIZE);
    benchmark::RunSpecifiedBenchmarks();

    return 0;
}
