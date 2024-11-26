/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/time.h>

#include <unistd.h>
#include <fcntl.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

/* Run environment:
 *  # show_gids | grep mlx5_2 | grep v2
 *    DEV  PORT  INDEX  GID                                      IPv4            VER   DEV
 *    ---  ----  -----  ---                                      ------------    ---   ---
 *  mlx5_2  1      0     fe80:0000:0000:0000:003c:baff:fe14:6bed                 v2      enp3s0f0s0
 *  mlx5_2  1      1     0000:0000:0000:0000:0000:ffff:c0a8:210d 192.168.33.13   v2      enp3s0f0s0
 *
 * Build:
 * $ gcc -o read_write_crc32c_perf read_write_crc32c_perf.c -libverbs -lmlx5
 *
 * Run:
 * 1) READ:  $ RDMA_READ=0 ./read_write_crc32c_perf mlx5_2
 * 2) WRITE: $ ./read_write_crc32c_perf mlx5_2
 */

/* structure of system resource */
struct resource {
    uint32_t buf_len;

    struct ibv_context *ib_ctx;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_qp *qp;

    struct ibv_mr *data_mr; /* MR for data buffer */
    struct ibv_mr *pi_mr;   /* MR for protection information buffer */

    struct mlx5dv_mkey *sig_mkey;
    uint32_t seed;
};

static int poll_completion(struct ibv_cq *cq)
{
    struct ibv_wc wc = {};
    int poll_result;

    do {
        poll_result = ibv_poll_cq(cq, 1, &wc);
    } while (poll_result == 0);

    return 0;
}

static struct mlx5dv_mkey *create_sig_mkey(struct ibv_pd *pd)
{
    struct mlx5dv_mkey_init_attr mkey_attr = {};
    mkey_attr.pd = pd;
    mkey_attr.max_entries = 1;
    mkey_attr.create_flags = MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT | MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE;
    struct mlx5dv_mkey *mkey;

    mkey = mlx5dv_create_mkey(&mkey_attr);
    if (!mkey)
        fprintf(stderr, "Error mlx5dv_create_mkey: %s\n", strerror(errno));

    return mkey;
}

static int destroy_sig_mkey(struct mlx5dv_mkey **mkey)
{
    int rc;

    if (!*mkey)
        return 0;

    rc = mlx5dv_destroy_mkey(*mkey);
    if (rc) {
        fprintf(stderr, "Error mlx5dv_destroy_mkey: %s\n", strerror(rc));
        return -1;
    }
    *mkey = NULL;

    return 0;
}

static int configure_sig_mkey(struct resource *res, struct mlx5dv_sig_block_attr *sig_attr)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
    struct mlx5dv_qp_ex *dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
    struct mlx5dv_mkey *mkey = res->sig_mkey;
    struct mlx5dv_mkey_conf_attr conf_attr = {};
    uint32_t access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;

    mlx5dv_wr_mkey_configure(dv_qp, mkey, 3, &conf_attr);
    mlx5dv_wr_set_mkey_access_flags(dv_qp, access_flags);

    struct mlx5dv_mr_interleaved mr_interleaved[2];
    /* data */
    mr_interleaved[0].addr = (uintptr_t)res->data_mr->addr;
    mr_interleaved[0].bytes_count = res->buf_len;
    mr_interleaved[0].bytes_skip = 0;
    mr_interleaved[0].lkey = res->data_mr->lkey;
    /* protection */
    mr_interleaved[1].addr = (uintptr_t)res->pi_mr->addr;
    mr_interleaved[1].bytes_count = sizeof(uint32_t); // 4 bytes for crc32c result
    mr_interleaved[1].bytes_skip = 0;
    mr_interleaved[1].lkey = res->pi_mr->lkey;

    mlx5dv_wr_set_mkey_layout_interleaved(dv_qp, 1, 2, mr_interleaved);
    mlx5dv_wr_set_mkey_sig_block(dv_qp, sig_attr);

    return ibv_wr_complete(qpx);
}

enum sig_mode {
    SIG_MODE_INSERT_ON_MEM,
};

static int reg_sig_mkey(struct resource *res, enum sig_mode mode)
{
    struct mlx5dv_sig_crc crc_sig;
    struct mlx5dv_sig_block_domain mem_domain;

    switch (mode) {
    case SIG_MODE_INSERT_ON_MEM:
        memset(&crc_sig, 0, sizeof(crc_sig));
        crc_sig.type = MLX5DV_SIG_CRC_TYPE_CRC32C;
        crc_sig.seed = res->seed;

        memset(&mem_domain, 0, sizeof(mem_domain));
        mem_domain.sig_type = MLX5DV_SIG_TYPE_CRC;
        mem_domain.block_size = res->buf_len == 4096 ? MLX5DV_BLOCK_SIZE_4096 : MLX5DV_BLOCK_SIZE_512;
        mem_domain.sig.crc = &crc_sig;
        break;
    default:
        break;
    }

    struct mlx5dv_sig_block_attr sig_attr = {
        .mem = &mem_domain,
        .check_mask = MLX5DV_SIG_MASK_CRC32C,
    };

    if (configure_sig_mkey(res, &sig_attr))
        return -1;

    poll_completion(res->qp->send_cq);

    return 0;
}

static int inv_sig_mkey(struct resource *res)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
    int rc;

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_SIGNALED;
    ibv_wr_local_inv(qpx, res->sig_mkey->rkey);
    rc = ibv_wr_complete(qpx);
    if (rc) {
        fprintf(stderr, "Error: Local invalidate sig MKEY: %s\n", strerror(rc));
        return -1;
    }

    poll_completion(res->qp->send_cq);

    return rc;
}

static int destroy_cq(struct ibv_cq **cq)
{
    int rc;

    if (!*cq)
        return 0;

    rc = ibv_destroy_cq(*cq);
    if (rc) {
        fprintf(stderr, "Error: ibv_destroy_cq: %s\n", strerror(rc));
        rc = -1;
    }
    *cq = NULL;

    return rc;
}

static struct ibv_qp *create_qp(struct ibv_context *ctxt, struct ibv_pd* pd, struct ibv_cq *rq_cq, struct ibv_cq *sq_cq)
{
    struct ibv_qp *qp;

    struct ibv_qp_cap qp_cap = {
        .max_send_wr = 68 + 64,
        .max_recv_wr = 1,
        .max_send_sge = 1,
        .max_recv_sge = 1,
        .max_inline_data = 512,
    };

    struct ibv_qp_init_attr_ex qp_attr = {
        .qp_context = NULL,
        .sq_sig_all = 0,
        .send_cq = sq_cq,
        .recv_cq = rq_cq,
        .cap = qp_cap,

        .qp_type = IBV_QPT_RC,
        .comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
        .pd = pd,
        .send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_RDMA_READ | IBV_QP_EX_WITH_LOCAL_INV,
    };

    /* signature specific attributes */
    struct mlx5dv_qp_init_attr qp_dv_attr = {
        .comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS,
        .send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
    };

    qp = mlx5dv_create_qp(ctxt, &qp_attr, &qp_dv_attr);
    if (!qp)
        fprintf(stderr, "Error: mlx5dv_create_qp: %s\n", strerror(errno));

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
        fprintf(stderr, "Error: ibv_dereg_mr: %s\n", strerror(rc));

    *mr = NULL;
    free(ptr);

    return rc;
}

struct ibv_mr * alloc_mr(struct ibv_pd *pd, size_t size)
{
    int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

    void *ptr = malloc(size);
    if (!ptr) {
        fprintf(stderr, "Error: calloc: %s\n", strerror(errno));
        return NULL;
    }
    memset(ptr, 'a', size); // data payload is filled with b'a'

    struct ibv_mr *mr = ibv_reg_mr(pd, ptr, size, mr_flags);
    if (!mr) {
        fprintf(stderr, "Error: ibv_reg_mr: %s\n", strerror(errno));
        free(ptr);
        return NULL;
    }

    return mr;
}

static int resources_destroy(struct resource *res)
{
    int rc = 0;

    ibv_destroy_qp(res->qp);

    if (destroy_sig_mkey(&res->sig_mkey)) rc = -1;

    if (free_mr(&res->pi_mr)) rc = -1;

    if (destroy_cq(&res->cq)) rc = -1;

    ibv_dealloc_pd(res->pd);

    ibv_close_device(res->ib_ctx);

    return rc;
}

struct ibv_context* get_dev_ctx(const char*dev_name)
{
    uint32_t dev_cnt = 0;
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

    struct ibv_context *ctxt = ibv_open_device(device);

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

uint32_t get_port_attr(struct ibv_context *ibv_ctx, struct ibv_port_attr *port_attr, uint8_t port_num)
{
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
                .flow_label = getenv("FL") ? 3 : 1,
                .hop_limit = 64,
                .sgid_index = 1,
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

struct resource* alloc_offload_res(char *dev_name)
{
    struct resource *res = malloc(sizeof(struct resource));

    res->ib_ctx = get_dev_ctx(dev_name);
    check_support_crc32c(res->ib_ctx);

    res->pd = ibv_alloc_pd(res->ib_ctx);
    res->cq = ibv_create_cq(res->ib_ctx, 16, NULL, NULL, 0);
    res->sig_mkey = create_sig_mkey(res->pd);
    res->qp = create_qp(res->ib_ctx, res->pd, res->cq, res->cq);
    init_qp(res->qp);
    qp_self_connected(res->qp);
    res->pi_mr = alloc_mr(res->pd, 4);

    return res;
}

int main(int argc, char *argv[])
{
    struct resource* res = alloc_offload_res(argv[1]);
    int rdma_read = getenv("RDMA_READ") ? 1 : 0;

    void *data_buf = malloc(4096);
    memset(data_buf, 'a', 4096);

    // Open /dev/random for reading
    int read_bytes = read(open("/dev/random", O_RDONLY), data_buf, 4096);
    if (-1 == read_bytes || 4096 != read_bytes) {
        fprintf(stderr, "Error reading from /dev/random\n");
        return -1;
    }

    res->buf_len = 4096;
    res->seed = 0;
    res->data_mr = ibv_reg_mr(res->pd, data_buf, 4096, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);

    if (reg_sig_mkey(res, SIG_MODE_INSERT_ON_MEM)) {
        fprintf(stderr, "Error: Failed reg sig mkey\n");
        return -1;
    }

    struct ibv_send_wr sr[64];
    struct ibv_sge sge;

    memset(sr, 0, sizeof(struct ibv_send_wr) * 64);
    memset(&sge, 0, sizeof(struct ibv_sge));
    if (!rdma_read) {
        sge.addr = (uintptr_t)res->data_mr->addr;
        sge.length = res->buf_len;
        sge.lkey = res->data_mr->lkey;

        for (int i = 0; i < 63; i++) {
            sr[i].next = &sr[i + 1];
            sr[i].sg_list = &sge;
            sr[i].num_sge = 1;
            sr[i].opcode = IBV_WR_RDMA_WRITE;
            sr[i].send_flags = 0;

            sr[i].wr.rdma.remote_addr = 0;
            sr[i].wr.rdma.rkey = res->sig_mkey->rkey;
        }
        sr[63].next = NULL;
        sr[63].sg_list = &sge;
        sr[63].num_sge = 1;
        sr[63].opcode = IBV_WR_RDMA_WRITE;
        sr[63].send_flags = IBV_SEND_SIGNALED;

        sr[63].wr.rdma.remote_addr = 0;
        sr[63].wr.rdma.rkey = res->sig_mkey->rkey;
    } else {
        sge.addr = 0;
        sge.length = res->buf_len;
        sge.lkey = res->sig_mkey->lkey;

        for (int i = 0; i < 63; i++) {
            sr[i].next = &sr[i + 1];
            sr[i].sg_list = &sge;
            sr[i].num_sge = 1;
            sr[i].opcode = IBV_WR_RDMA_READ;
            sr[i].send_flags = 0;

            sr[i].wr.rdma.remote_addr = (uintptr_t)res->data_mr->addr;
            sr[i].wr.rdma.rkey = res->data_mr->rkey;
        }

        sr[63].next = NULL;
        sr[63].sg_list = &sge;
        sr[63].num_sge = 1;
        sr[63].opcode = IBV_WR_RDMA_READ;
        sr[63].send_flags = IBV_SEND_SIGNALED;

        sr[63].wr.rdma.remote_addr = (uintptr_t)res->data_mr->addr;
        sr[63].wr.rdma.rkey = res->data_mr->rkey;
    }

    struct ibv_send_wr *bad_wr = NULL;

    if (ibv_post_send(res->qp, sr, &bad_wr)) {
        fprintf(stderr, "Error: ibv_post_send failed: opcode IBV_WR_RDMA_READ\n");
        return -1;
    }

    int i = 0;
    double start_time_ms, cur_time_ms;
    struct timeval cur_time;
    gettimeofday(&cur_time, NULL);
    start_time_ms = (double)(cur_time.tv_sec * 1000) + (((double)cur_time.tv_usec) / 1000.0);

    if (ibv_post_send(res->qp, sr, &bad_wr)) {
        fprintf(stderr, "Error: ibv_post_send failed: opcode IBV_WR_RDMA_READ\n");
        return -1;
    }

    while (1) {
        poll_completion(res->qp->send_cq);
        if ((i + 1) % 100000 == 0) { // 64 * 4096 * 10000 * 8 / 1000000
            gettimeofday(&cur_time, NULL);
            cur_time_ms = (double)(cur_time.tv_sec * 1000) + (((double)cur_time.tv_usec) / 1000.0);
            printf("BW: %f Mbps\n", (double)(209715200) / (cur_time_ms - start_time_ms));
            start_time_ms = cur_time_ms;
        }
        i++;

        if (ibv_post_send(res->qp, sr, &bad_wr)) {
            fprintf(stderr, "Error: ibv_post_send failed: opcode IBV_WR_RDMA_READ\n");
            return -1;
        }
    }

    poll_completion(res->qp->send_cq);

    if (inv_sig_mkey(res)) {
        fprintf(stderr, "Error: failed to clear sig mkey\n");
        return -1;
    }

    ibv_dereg_mr(res->data_mr);

free_res_and_exit:
    free(data_buf);
    if (resources_destroy(res)) return -1;

    return 0;
}
