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
 * $ gcc -DMR_OPT -o crc32c_simple_perf crc32c_simple_perf.c -libverbs -lmlx5
 *
 * Run:
 * $ ./crc32c_simple_perf mlx5_2
 */

const uint32_t crc32c_table[256] = {
    0xad7d5351, 0x5f16d052, 0x4c4623a6, 0xbe2da0a5, 0x6ae7c44e, 0x988c474d, 0x8bdcb4b9, 0x79b737ba,
    0x27a40b9e, 0xd5cf889d, 0xc69f7b69, 0x34f4f86a, 0xe03e9c81, 0x12551f82, 0x0105ec76, 0xf36e6f75,
    0xbd23943e, 0x4f48173d, 0x5c18e4c9, 0xae7367ca, 0x7ab90321, 0x88d28022, 0x9b8273d6, 0x69e9f0d5,
    0x37faccf1, 0xc5914ff2, 0xd6c1bc06, 0x24aa3f05, 0xf0605bee, 0x020bd8ed, 0x115b2b19, 0xe330a81a,
    0x8dc0dd8f, 0x7fab5e8c, 0x6cfbad78, 0x9e902e7b, 0x4a5a4a90, 0xb831c993, 0xab613a67, 0x590ab964,
    0x07198540, 0xf5720643, 0xe622f5b7, 0x144976b4, 0xc083125f, 0x32e8915c, 0x21b862a8, 0xd3d3e1ab,
    0x9d9e1ae0, 0x6ff599e3, 0x7ca56a17, 0x8ecee914, 0x5a048dff, 0xa86f0efc, 0xbb3ffd08, 0x49547e0b,
    0x1747422f, 0xe52cc12c, 0xf67c32d8, 0x0417b1db, 0xd0ddd530, 0x22b65633, 0x31e6a5c7, 0xc38d26c4,
    0xec064eed, 0x1e6dcdee, 0x0d3d3e1a, 0xff56bd19, 0x2b9cd9f2, 0xd9f75af1, 0xcaa7a905, 0x38cc2a06,
    0x66df1622, 0x94b49521, 0x87e466d5, 0x758fe5d6, 0xa145813d, 0x532e023e, 0x407ef1ca, 0xb21572c9,
    0xfc588982, 0x0e330a81, 0x1d63f975, 0xef087a76, 0x3bc21e9d, 0xc9a99d9e, 0xdaf96e6a, 0x2892ed69,
    0x7681d14d, 0x84ea524e, 0x97baa1ba, 0x65d122b9, 0xb11b4652, 0x4370c551, 0x502036a5, 0xa24bb5a6,
    0xccbbc033, 0x3ed04330, 0x2d80b0c4, 0xdfeb33c7, 0x0b21572c, 0xf94ad42f, 0xea1a27db, 0x1871a4d8,
    0x466298fc, 0xb4091bff, 0xa759e80b, 0x55326b08, 0x81f80fe3, 0x73938ce0, 0x60c37f14, 0x92a8fc17,
    0xdce5075c, 0x2e8e845f, 0x3dde77ab, 0xcfb5f4a8, 0x1b7f9043, 0xe9141340, 0xfa44e0b4, 0x082f63b7,
    0x563c5f93, 0xa457dc90, 0xb7072f64, 0x456cac67, 0x91a6c88c, 0x63cd4b8f, 0x709db87b, 0x82f63b78,
    0x2f8b6829, 0xdde0eb2a, 0xceb018de, 0x3cdb9bdd, 0xe811ff36, 0x1a7a7c35, 0x092a8fc1, 0xfb410cc2,
    0xa55230e6, 0x5739b3e5, 0x44694011, 0xb602c312, 0x62c8a7f9, 0x90a324fa, 0x83f3d70e, 0x7198540d,
    0x3fd5af46, 0xcdbe2c45, 0xdeeedfb1, 0x2c855cb2, 0xf84f3859, 0x0a24bb5a, 0x197448ae, 0xeb1fcbad,
    0xb50cf789, 0x4767748a, 0x5437877e, 0xa65c047d, 0x72966096, 0x80fde395, 0x93ad1061, 0x61c69362,
    0x0f36e6f7, 0xfd5d65f4, 0xee0d9600, 0x1c661503, 0xc8ac71e8, 0x3ac7f2eb, 0x2997011f, 0xdbfc821c,
    0x85efbe38, 0x77843d3b, 0x64d4cecf, 0x96bf4dcc, 0x42752927, 0xb01eaa24, 0xa34e59d0, 0x5125dad3,
    0x1f682198, 0xed03a29b, 0xfe53516f, 0x0c38d26c, 0xd8f2b687, 0x2a993584, 0x39c9c670, 0xcba24573,
    0x95b17957, 0x67dafa54, 0x748a09a0, 0x86e18aa3, 0x522bee48, 0xa0406d4b, 0xb3109ebf, 0x417b1dbc,
    0x6ef07595, 0x9c9bf696, 0x8fcb0562, 0x7da08661, 0xa96ae28a, 0x5b016189, 0x4851927d, 0xba3a117e,
    0xe4292d5a, 0x1642ae59, 0x05125dad, 0xf779deae, 0x23b3ba45, 0xd1d83946, 0xc288cab2, 0x30e349b1,
    0x7eaeb2fa, 0x8cc531f9, 0x9f95c20d, 0x6dfe410e, 0xb93425e5, 0x4b5fa6e6, 0x580f5512, 0xaa64d611,
    0xf477ea35, 0x061c6936, 0x154c9ac2, 0xe72719c1, 0x33ed7d2a, 0xc186fe29, 0xd2d60ddd, 0x20bd8ede,
    0x4e4dfb4b, 0xbc267848, 0xaf768bbc, 0x5d1d08bf, 0x89d76c54, 0x7bbcef57, 0x68ec1ca3, 0x9a879fa0,
    0xc494a384, 0x36ff2087, 0x25afd373, 0xd7c45070, 0x030e349b, 0xf165b798, 0xe235446c, 0x105ec76f,
    0x5e133c24, 0xac78bf27, 0xbf284cd3, 0x4d43cfd0, 0x9989ab3b, 0x6be22838, 0x78b2dbcc, 0x8ad958cf,
    0xd4ca64eb, 0x26a1e7e8, 0x35f1141c, 0xc79a971f, 0x1350f3f4, 0xe13b70f7, 0xf26b8303, 0x00000000
};

uint32_t crc32c(uint32_t crc, const void *_data, size_t length)
{
    const uint8_t *data = (const uint8_t *) _data;
    while (length--) {
        crc = crc32c_table[~(*data++ ^ crc) & 0xFF] ^ (crc >> 8);
    }
    return crc;
}

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

static int poll_completion(struct ibv_cq *cq, enum ibv_wc_opcode expected)
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

    poll_completion(res->qp->send_cq, IBV_WC_DRIVER1);

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

    poll_completion(res->qp->send_cq, IBV_WC_LOCAL_INV);

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
        .max_send_wr = 2,
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

uint32_t dv_get_crc32c(struct resource *res, uint32_t crc, void *data, size_t length)
{
#ifndef MR_OPT
    res->buf_len = length;
    res->seed = crc;
    res->data_mr = ibv_reg_mr(res->pd, data, res->buf_len, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);

    if (reg_sig_mkey(res, SIG_MODE_INSERT_ON_MEM)) {
        fprintf(stderr, "Error: Failed reg sig mkey\n");
        return -1;
    }
#endif

    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    sge.addr = 0;
    sge.length = res->buf_len;
    sge.lkey = res->sig_mkey->lkey;

    struct ibv_send_wr sr;
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_RDMA_READ;
    sr.send_flags = IBV_SEND_SIGNALED;

    sr.wr.rdma.remote_addr = (uintptr_t)res->data_mr->addr;
    sr.wr.rdma.rkey = res->data_mr->rkey;

    if (ibv_post_send(res->qp, &sr, &bad_wr)) {
        fprintf(stderr, "Error: ibv_post_send failed: opcode IBV_WR_RDMA_READ\n");
        return -1;
    }
    poll_completion(res->qp->send_cq, IBV_WC_RDMA_READ);

#ifndef MR_OPT
    if (inv_sig_mkey(res)) {
        fprintf(stderr, "Error: failed to clear sig mkey\n");
        return -1;
    }
    if (ibv_dereg_mr(res->data_mr)) {
        fprintf(stderr, "Error: failed to dereg mr\n");
        return -1;
    }
#endif

    return *(uint32_t*)res->pi_mr->addr ^ 0xffffffff;
}

int main(int argc, char *argv[])
{
    struct resource* res = alloc_offload_res(argv[1]);

    uint32_t length = 1 * 1024 * 1024 * 1024;
    void *data_buf = malloc(length);
    if (data_buf == NULL) {
        fprintf(stderr, "Failed to allocate 2GB buffer\n");
    }
    memset(data_buf, 'a', length);
    uint32_t data_chunk = length / 4096;

    // Open /dev/random for reading
    int fd = open("/dev/random", O_RDONLY);
    for (int i = 0; i < data_chunk; i++) {
        int read_bytes = read(fd, data_buf + i * 4096, 4096);
        if (-1 == read_bytes || 4096 != read_bytes) {
            fprintf(stderr, "Error reading from /dev/random\n");
            return -1;
        }
    }
    close(fd);

    uint32_t sw_crc32c;
    uint32_t hw_crc32c;
    uint32_t run_times = 10;
    unsigned long hw_us = 0;
    struct timeval cur_time;
    unsigned long start_time_us, cur_time_us;

    for (int j = 0; j < data_chunk; j++) {
        #ifdef MR_OPT
            res->buf_len = 4096;
            res->seed = 0;
            res->data_mr = ibv_reg_mr(res->pd, data_buf + 4096 * j, 4096, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);

            if (reg_sig_mkey(res, SIG_MODE_INSERT_ON_MEM)) {
                fprintf(stderr, "Error: Failed reg sig mkey\n");
                return -1;
            }
        #endif
        gettimeofday(&cur_time, NULL);
        unsigned long start_time_us = (cur_time.tv_sec * 1000000) + (cur_time.tv_usec);
        for (int i = 0; i < run_times; i++) {
            hw_crc32c = dv_get_crc32c(res, 0, data_buf + 4096 * j, 4096);
        }
        gettimeofday(&cur_time, NULL);
        cur_time_us = (cur_time.tv_sec * 1000000) + (cur_time.tv_usec);
        hw_us += (cur_time_us - start_time_us);

        #ifdef MR_OPT
            if (inv_sig_mkey(res)) {
                fprintf(stderr, "Error: failed to clear sig mkey\n");
                return -1;
            }
            if (ibv_dereg_mr(res->data_mr)) {
                fprintf(stderr, "Error: failed to dereg mr\n");
                return -1;
            }
        #endif
    }

    gettimeofday(&cur_time, NULL);
    start_time_us = (cur_time.tv_sec * 1000000) + (cur_time.tv_usec);
    for (int j = 0; j < data_chunk; j++) {
        for (int i = 0; i < run_times; i++) {
            sw_crc32c = crc32c(0, data_buf + 4096 * j, 4096);
        }
    }
    gettimeofday(&cur_time, NULL);
    cur_time_us = (cur_time.tv_sec * 1000000) + (cur_time.tv_usec);
    unsigned long sw_us = cur_time_us - start_time_us;

    if (hw_crc32c != sw_crc32c) {
        fprintf(stderr, "hw_crc32c:0x%08x != sw_crc32c:0x%08x\n", hw_crc32c, sw_crc32c);
    } else {
        printf("block CRC32C: 0x%08x, hw_us:%fus, sw_us:%fus\n", hw_crc32c, ((float)hw_us) / run_times / data_chunk, ((float)sw_us) / run_times / data_chunk);
    }

free_res_and_exit:
    if (resources_destroy(res)) return -1;

    return 0;
}
