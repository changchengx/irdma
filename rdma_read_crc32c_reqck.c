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

//#define info(format, arg...) fprintf(stdout, format, ##arg)
#define info(format, arg...)
#define err(format, arg...) fprintf(stderr, "ERROR: " format, ##arg)

// https://web.mit.edu/freebsd/head/sys/libkern/crc32.c

/* CRC32C routines, these use a different polynomial */
/*****************************************************************/
/*                                                               */
/* CRC LOOKUP TABLE                                              */
/* ================                                              */
/* The following CRC lookup table was generated automagically    */
/* by the Rocksoft^tm Model CRC Algorithm Table Generation       */
/* Program V1.0 using the following model parameters:            */
/*                                                               */
/*    Width   : 4 bytes.                                         */
/*    Poly    : 0x1EDC6F41L                                      */
/*    Reverse : TRUE.                                            */
/*                                                               */
/* For more information on the Rocksoft^tm Model CRC Algorithm,  */
/* see the document titled "A Painless Guide to CRC Error        */
/* Detection Algorithms" by Ross Williams                        */
/* (ross@guest.adelaide.edu.au.). This document is likely to be  */
/* in the FTP archive "ftp.adelaide.edu.au/pub/rocksoft".        */
/*                                                               */
/*****************************************************************/

static const uint32_t crc32Table[256] = {
    0x00000000L, 0xF26B8303L, 0xE13B70F7L, 0x1350F3F4L,
    0xC79A971FL, 0x35F1141CL, 0x26A1E7E8L, 0xD4CA64EBL,
    0x8AD958CFL, 0x78B2DBCCL, 0x6BE22838L, 0x9989AB3BL,
    0x4D43CFD0L, 0xBF284CD3L, 0xAC78BF27L, 0x5E133C24L,
    0x105EC76FL, 0xE235446CL, 0xF165B798L, 0x030E349BL,
    0xD7C45070L, 0x25AFD373L, 0x36FF2087L, 0xC494A384L,
    0x9A879FA0L, 0x68EC1CA3L, 0x7BBCEF57L, 0x89D76C54L,
    0x5D1D08BFL, 0xAF768BBCL, 0xBC267848L, 0x4E4DFB4BL,
    0x20BD8EDEL, 0xD2D60DDDL, 0xC186FE29L, 0x33ED7D2AL,
    0xE72719C1L, 0x154C9AC2L, 0x061C6936L, 0xF477EA35L,
    0xAA64D611L, 0x580F5512L, 0x4B5FA6E6L, 0xB93425E5L,
    0x6DFE410EL, 0x9F95C20DL, 0x8CC531F9L, 0x7EAEB2FAL,
    0x30E349B1L, 0xC288CAB2L, 0xD1D83946L, 0x23B3BA45L,
    0xF779DEAEL, 0x05125DADL, 0x1642AE59L, 0xE4292D5AL,
    0xBA3A117EL, 0x4851927DL, 0x5B016189L, 0xA96AE28AL,
    0x7DA08661L, 0x8FCB0562L, 0x9C9BF696L, 0x6EF07595L,
    0x417B1DBCL, 0xB3109EBFL, 0xA0406D4BL, 0x522BEE48L,
    0x86E18AA3L, 0x748A09A0L, 0x67DAFA54L, 0x95B17957L,
    0xCBA24573L, 0x39C9C670L, 0x2A993584L, 0xD8F2B687L,
    0x0C38D26CL, 0xFE53516FL, 0xED03A29BL, 0x1F682198L,
    0x5125DAD3L, 0xA34E59D0L, 0xB01EAA24L, 0x42752927L,
    0x96BF4DCCL, 0x64D4CECFL, 0x77843D3BL, 0x85EFBE38L,
    0xDBFC821CL, 0x2997011FL, 0x3AC7F2EBL, 0xC8AC71E8L,
    0x1C661503L, 0xEE0D9600L, 0xFD5D65F4L, 0x0F36E6F7L,
    0x61C69362L, 0x93AD1061L, 0x80FDE395L, 0x72966096L,
    0xA65C047DL, 0x5437877EL, 0x4767748AL, 0xB50CF789L,
    0xEB1FCBADL, 0x197448AEL, 0x0A24BB5AL, 0xF84F3859L,
    0x2C855CB2L, 0xDEEEDFB1L, 0xCDBE2C45L, 0x3FD5AF46L,
    0x7198540DL, 0x83F3D70EL, 0x90A324FAL, 0x62C8A7F9L,
    0xB602C312L, 0x44694011L, 0x5739B3E5L, 0xA55230E6L,
    0xFB410CC2L, 0x092A8FC1L, 0x1A7A7C35L, 0xE811FF36L,
    0x3CDB9BDDL, 0xCEB018DEL, 0xDDE0EB2AL, 0x2F8B6829L,
    0x82F63B78L, 0x709DB87BL, 0x63CD4B8FL, 0x91A6C88CL,
    0x456CAC67L, 0xB7072F64L, 0xA457DC90L, 0x563C5F93L,
    0x082F63B7L, 0xFA44E0B4L, 0xE9141340L, 0x1B7F9043L,
    0xCFB5F4A8L, 0x3DDE77ABL, 0x2E8E845FL, 0xDCE5075CL,
    0x92A8FC17L, 0x60C37F14L, 0x73938CE0L, 0x81F80FE3L,
    0x55326B08L, 0xA759E80BL, 0xB4091BFFL, 0x466298FCL,
    0x1871A4D8L, 0xEA1A27DBL, 0xF94AD42FL, 0x0B21572CL,
    0xDFEB33C7L, 0x2D80B0C4L, 0x3ED04330L, 0xCCBBC033L,
    0xA24BB5A6L, 0x502036A5L, 0x4370C551L, 0xB11B4652L,
    0x65D122B9L, 0x97BAA1BAL, 0x84EA524EL, 0x7681D14DL,
    0x2892ED69L, 0xDAF96E6AL, 0xC9A99D9EL, 0x3BC21E9DL,
    0xEF087A76L, 0x1D63F975L, 0x0E330A81L, 0xFC588982L,
    0xB21572C9L, 0x407EF1CAL, 0x532E023EL, 0xA145813DL,
    0x758FE5D6L, 0x87E466D5L, 0x94B49521L, 0x66DF1622L,
    0x38CC2A06L, 0xCAA7A905L, 0xD9F75AF1L, 0x2B9CD9F2L,
    0xFF56BD19L, 0x0D3D3E1AL, 0x1E6DCDEEL, 0xEC064EEDL,
    0xC38D26C4L, 0x31E6A5C7L, 0x22B65633L, 0xD0DDD530L,
    0x0417B1DBL, 0xF67C32D8L, 0xE52CC12CL, 0x1747422FL,
    0x49547E0BL, 0xBB3FFD08L, 0xA86F0EFCL, 0x5A048DFFL,
    0x8ECEE914L, 0x7CA56A17L, 0x6FF599E3L, 0x9D9E1AE0L,
    0xD3D3E1ABL, 0x21B862A8L, 0x32E8915CL, 0xC083125FL,
    0x144976B4L, 0xE622F5B7L, 0xF5720643L, 0x07198540L,
    0x590AB964L, 0xAB613A67L, 0xB831C993L, 0x4A5A4A90L,
    0x9E902E7BL, 0x6CFBAD78L, 0x7FAB5E8CL, 0x8DC0DD8FL,
    0xE330A81AL, 0x115B2B19L, 0x020BD8EDL, 0xF0605BEEL,
    0x24AA3F05L, 0xD6C1BC06L, 0xC5914FF2L, 0x37FACCF1L,
    0x69E9F0D5L, 0x9B8273D6L, 0x88D28022L, 0x7AB90321L,
    0xAE7367CAL, 0x5C18E4C9L, 0x4F48173DL, 0xBD23943EL,
    0xF36E6F75L, 0x0105EC76L, 0x12551F82L, 0xE03E9C81L,
    0x34F4F86AL, 0xC69F7B69L, 0xD5CF889DL, 0x27A40B9EL,
    0x79B737BAL, 0x8BDCB4B9L, 0x988C474DL, 0x6AE7C44EL,
    0xBE2DA0A5L, 0x4C4623A6L, 0x5F16D052L, 0xAD7D5351L
};

/* pseudo code:
 *   char data[512] = {  'a'\+512 };
 *   crc32c(data, 512, 0); // result should be: python3.12 import crc32c, hex(crc32c.crc32c(b"a" * 512))
 */
static uint32_t crc32c(const void *buf, size_t len, uint32_t crc)
{
    const uint8_t *p = (const uint8_t *)buf;

    crc = ~crc;
    while (len--) {
        crc = crc32Table[(crc ^ *p++) & 0xFF] ^ (crc >> 8);
    }
    return ~crc;
}

struct com_res {
    struct ibv_context *ib_ctx;
    struct ibv_pd *pd;
    union ibv_gid gid;
};

struct cm_con_data {
    uint64_t addr;   /* Buffer address */
    uint32_t rkey;   /* Remote key */
    uint32_t qp_num; /* QP number */
    uint8_t gid[16]; /* gid */
}__attribute__((packed));

/* structure of system resources */
struct resources {
    struct com_res *gres;
    struct cm_con_data peer_info;

    struct ibv_cq *send_cq;
    struct ibv_cq *recv_cq;
    struct ibv_qp *qp;

    struct ibv_mr *data_mr; /* MR for data buffer */
    struct ibv_mr *pi_mr;       /* MR for protection information buffer */

    struct mlx5dv_mkey *sig_mkey;
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
    info("CQE status %s, opcode %s:%d\n", ibv_wc_status_str(wc.status),
         wc_opcode_str(wc.opcode), wc.opcode);

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

enum sig_mode {
    SIG_MODE_INSERT_ON_MEM,  //max_send_wr >= 2
    SIG_MODE_INSERT_ON_WIRE, //max_send_wr >= 2
    SIG_MODE_CHECK_MEM_WIRE, //max_send_wr >= 4
};

static int configure_sig_mkey(struct resources *res, enum sig_mode mode, struct mlx5dv_sig_block_attr *sig_attr)
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

    if (mode == SIG_MODE_INSERT_ON_WIRE) {
        struct ibv_sge sge;
        sge.addr = (uintptr_t)res->data_mr->addr;
        sge.lkey = res->data_mr->lkey;
        sge.length = 4096;
        mlx5dv_wr_set_mkey_layout_list(dv_qp, 1, &sge);
    } else if (mode == SIG_MODE_INSERT_ON_MEM || mode == SIG_MODE_CHECK_MEM_WIRE) {
        struct mlx5dv_mr_interleaved mr_interleaved[2];
        /* data */
        mr_interleaved[0].addr = (uintptr_t)res->data_mr->addr;
        mr_interleaved[0].bytes_count = 4096;
        mr_interleaved[0].bytes_skip = 0;
        mr_interleaved[0].lkey = res->data_mr->lkey;
        /* protection */
        mr_interleaved[1].addr = (uintptr_t)res->pi_mr->addr;
        mr_interleaved[1].bytes_count = sizeof(uint32_t); // 4 bytes for crc32c result
        mr_interleaved[1].bytes_skip = 0;
        mr_interleaved[1].lkey = res->pi_mr->lkey;

        mlx5dv_wr_set_mkey_layout_interleaved(dv_qp, 1, 2, mr_interleaved);
    } else {
        fprintf(stderr, "Unsupported sig mode\n");
        return -1;
    }

    mlx5dv_wr_set_mkey_sig_block(dv_qp, sig_attr);

    return ibv_wr_complete(qpx);
}

static
void set_sig_domain_crc32c(struct mlx5dv_sig_block_domain *domain,
        struct mlx5dv_sig_crc *crc)
{
    memset(crc, 0, sizeof(*crc));
    crc->type = MLX5DV_SIG_CRC_TYPE_CRC32C;
    crc->seed = 0xffffffff; // For the Customer_A, seed should be 0;

    memset(domain, 0, sizeof(*domain));
    domain->sig_type = MLX5DV_SIG_TYPE_CRC;
    domain->block_size = MLX5DV_BLOCK_SIZE_4096;
    domain->sig.crc = crc;
}

static int reg_sig_mkey(struct resources *res, enum sig_mode mode)
{
    struct mlx5dv_sig_crc crc_mem_sig;
    struct mlx5dv_sig_block_domain mem_domain;

    struct mlx5dv_sig_crc crc_wire_sig;
    struct mlx5dv_sig_block_domain wire_domain;

    struct mlx5dv_sig_block_attr sig_attr = {
        .check_mask = MLX5DV_SIG_MASK_CRC32C,
    };

    switch (mode) {
    case SIG_MODE_INSERT_ON_MEM:
        set_sig_domain_crc32c(&mem_domain, &crc_mem_sig);

        sig_attr.mem = &mem_domain;
        break;
    case SIG_MODE_INSERT_ON_WIRE:
        set_sig_domain_crc32c(&wire_domain, &crc_wire_sig);

        sig_attr.wire = &wire_domain;
        break;
    case SIG_MODE_CHECK_MEM_WIRE:
        set_sig_domain_crc32c(&mem_domain, &crc_mem_sig);
        set_sig_domain_crc32c(&wire_domain, &crc_wire_sig);

        sig_attr.mem = &mem_domain;
        sig_attr.wire = &wire_domain;
    default:
        break;
    }

    if (configure_sig_mkey(res, mode, &sig_attr))
        return -1;

    info("Post mkey configure WR, opcode DRIVER1\n");

    if (poll_completion(res->qp->send_cq, IBV_WC_DRIVER1)) {
        err("Failed to configure sig MKEY\n");
        return -1;
    }
    info("Sig MKEY is configured\n");

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

    if (!sig_err)
        info("SIG status: OK\n");
    else
        info("SIG ERROR: %s: expected 0x%lx, actual 0x%lx, offset %lu\n",
             sig_err_str, err_info.err.sig.expected_value,
             err_info.err.sig.actual_value, err_info.err.sig.offset);

    return sig_err;
}

static int inv_sig_mkey(struct resources *res)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
    int rc;

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_SIGNALED;
    ibv_wr_local_inv(qpx, res->sig_mkey->rkey);
    rc = ibv_wr_complete(qpx);
    if (rc) {
        err("Local invalidate sig MKEY: %s\n", strerror(rc));
        return -1;
    }

    if (poll_completion(res->qp->send_cq, IBV_WC_LOCAL_INV)) {
        err("Failed to invalidete sig MKEY\n");
        return -1;
    }

    info("Sig MKEY is invalidated\n");

    return rc;
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
        .max_send_wr = 4,
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
        .send_ops_flags = IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_RDMA_READ | IBV_QP_EX_WITH_LOCAL_INV,
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
    int mr_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

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

    if (destroy_sig_mkey(&res->sig_mkey)) rc = -1;

    if (free_mr(&res->pi_mr)) rc = -1;

    if (free_mr(&res->data_mr)) rc = -1;

    if (destroy_cq(&res->send_cq)) rc = -1;
    if (destroy_cq(&res->recv_cq)) rc = -1;

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
    if (lid) *lid = port_attr.lid;

    if (ibv_query_gid(ibv_ctx, 1, 3, gid)) {
        printf("failed to query port gid\n");
        exit(__LINE__);
    }

    return 0;
}

uint32_t qp_connection_establish(struct ibv_qp* qp, uint32_t peer_qpn, void* peer_gid)
{
    union ibv_gid dgid = {};
    memcpy(&dgid, peer_gid, 16);

    enum ibv_qp_attr_mask mask = IBV_QP_STATE | IBV_QP_AV | \
        IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | \
        IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    struct ibv_qp_attr qpa = {
        .qp_state = IBV_QPS_RTR,
        .path_mtu = IBV_MTU_1024,
        .dest_qp_num = peer_qpn,
        .rq_psn = 0,
        .max_dest_rd_atomic = 1,
        .min_rnr_timer = 0x12,
        .ah_attr = {
            .is_global = 1,
            .port_num = 1,
            .grh = {
                .hop_limit = 64,
                .sgid_index = 3,
                .dgid = dgid
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

int main(int argc, char *argv[])
{
    char *dev_name = strdup(argv[1]);
    struct com_res gres = {};
    gres.ib_ctx = get_dev_ctx(dev_name);
    gres.pd = ibv_alloc_pd(gres.ib_ctx);
    check_support_crc32c(gres.ib_ctx);
    query_gid_lid(gres.ib_ctx, &gres.gid, NULL);

    struct resources requestor = {};
    requestor.gres = &gres;

    requestor.send_cq = ibv_create_cq(requestor.gres->ib_ctx, 16, NULL, NULL, 0);
    requestor.recv_cq = ibv_create_cq(requestor.gres->ib_ctx, 16, NULL, NULL, 0);
    requestor.data_mr = alloc_mr(requestor.gres->pd, 4096);
    requestor.pi_mr = alloc_mr(requestor.gres->pd, 4);
    memset(requestor.data_mr->addr, 0, 4096);
    memset(requestor.pi_mr->addr, 0, 4);
    requestor.sig_mkey = create_sig_mkey(requestor.gres->pd);
    requestor.qp = create_qp(requestor.gres->ib_ctx, requestor.gres->pd, requestor.recv_cq, requestor.send_cq);
    init_qp(requestor.qp);

    struct resources responser = {};
    responser.gres = &gres;

    responser.send_cq = ibv_create_cq(responser.gres->ib_ctx, 16, NULL, NULL, 0);
    responser.recv_cq = ibv_create_cq(responser.gres->ib_ctx, 16, NULL, NULL, 0);
    responser.data_mr = alloc_mr(responser.gres->pd, 4096);
    responser.pi_mr = alloc_mr(responser.gres->pd, 4);
    responser.sig_mkey = create_sig_mkey(responser.gres->pd);
    responser.qp = create_qp(responser.gres->ib_ctx, responser.gres->pd, responser.recv_cq, responser.send_cq);
    init_qp(responser.qp);

    requestor.peer_info.addr = 0;
    requestor.peer_info.rkey = responser.sig_mkey->rkey;
    requestor.peer_info.qp_num = responser.qp->qp_num;
    memcpy(requestor.peer_info.gid, gres.gid.raw, 16);

    responser.peer_info.addr = (uintptr_t)requestor.data_mr->addr;
    responser.peer_info.rkey = requestor.data_mr->rkey;
    responser.peer_info.qp_num = requestor.qp->qp_num;
    memcpy(responser.peer_info.gid, gres.gid.raw, 16);

    qp_connection_establish(requestor.qp, requestor.peer_info.qp_num, requestor.peer_info.gid);
    qp_connection_establish(responser.qp, responser.peer_info.qp_num, responser.peer_info.gid);

    if (reg_sig_mkey(&requestor, SIG_MODE_CHECK_MEM_WIRE))
        return -1;

    if (reg_sig_mkey(&responser, SIG_MODE_INSERT_ON_WIRE))
        return -1;

    struct ibv_send_wr sr;
    struct ibv_sge sge;
    struct ibv_send_wr *bad_wr = NULL;

    sge.addr = 0; //it's 0 here(base zero), do not use data_mr->addr
    sge.length = 4096 + 4; //it's 4096 + 4 here because it's attched with wire domain
    sge.lkey = requestor.sig_mkey->lkey;

    /* prepare the send work request */
    memset(&sr, 0, sizeof(sr));
    sr.next = NULL;
    sr.sg_list = &sge;
    sr.num_sge = 1;
    sr.opcode = IBV_WR_RDMA_READ;
    sr.send_flags = IBV_SEND_SIGNALED;

    sr.wr.rdma.remote_addr = requestor.peer_info.addr;
    sr.wr.rdma.rkey = requestor.peer_info.rkey;

    // Open /dev/random for reading
    int read_bytes = read(open("/dev/random", O_RDONLY), responser.data_mr->addr, 4096);
    if (-1 == read_bytes || 4096 != read_bytes) {
        fprintf(stderr, "Error reading from /dev/random\n");
        return -1;
    }

    if (ibv_post_send(requestor.qp, &sr, &bad_wr)) {
        err("ibv_post_send failed: opcode IBV_WR_RDMA_READ\n");
        return -1;
    }
    if (poll_completion(requestor.qp->send_cq, IBV_WC_RDMA_READ))
        return -1;

    if (check_sig_mkey(requestor.sig_mkey) < 0) return -1;

    uint32_t hw_crc32c = *(uint32_t *)requestor.pi_mr->addr; // For the Customer_A, XOR 0xFFFFFFFF
    uint32_t sw_crc32c = crc32c(responser.data_mr->addr, 4096, 0);
    printf("hw:0x%08x, sw:0x%08x\n", hw_crc32c, sw_crc32c);
    if (hw_crc32c != sw_crc32c) {
        for (ssize_t i = 0; i < read_bytes; i++) {
            printf("%02x ", ((char*)(responser.data_mr->addr))[i]);
            if ((i + 1) % 32 == 0) {
                printf("\n");
            }
        }
    }

    if (inv_sig_mkey(&requestor)) return -1;

free_res_and_exit:
    if (resources_destroy(&requestor)) return -1;

    if (resources_destroy(&responser)) return -1;

    ibv_dealloc_pd(gres.pd);
    ibv_close_device(gres.ib_ctx);

    return 0;
}
