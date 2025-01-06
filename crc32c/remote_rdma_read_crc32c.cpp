/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <byteswap.h>
#include <getopt.h>
#include <sys/time.h>
#include <netdb.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

/* poll CQ timeout in millisec (2 seconds) */
#define MAX_POLL_CQ_TIMEOUT 2000
#define CQ_SIZE 16

#define CRC32C_BLOCK_SIZE 4096

#ifndef MAX_CRC_TASK_SIZE
#define MAX_CRC_TASK_SIZE 16
#endif

#define info(format, arg...) fprintf(stdout, format, ##arg)
#define err(format, arg...) fprintf(stderr, "ERROR: " format, ##arg)

#if __BYTE_ORDER == __LITTLE_ENDIAN
static inline uint64_t htonll(uint64_t x) {return bswap_64(x);}
static inline uint64_t ntohll(uint64_t x) {return bswap_64(x);}
#elif __BYTE_ORDER == __BIG_ENDIAN
static inline uint64_t htonll(uint64_t x) {return x;}
static inline uint64_t ntohll(uint64_t x) {return x;}
#else
#error __BYTE_ORDER is neither __LITTLEN_ENDIAN nor __BIG_ENDIAN
#endif

/* struct of test parameters */
struct config_t {
    const char *dev_name;    /* IB device name */
    char       *server_name; /* server host anme */
    uint32_t   tcp_port;     /* server TCP port */
    uint8_t    ib_port;      /* local IB port work with */
    uint8_t    gid_idx;      /* gid index to use */
};

/* structure to exchange data which is needed to connect to QPs */
struct cm_con_data_t {
    uint64_t addr;   /* Buffer address */
    uint32_t rkey;   /* Remote key */
    uint32_t qp_num; /* QP number */
    uint8_t gid[16]; /* gid */
}__attribute__((packed));

/* structure of system resources */
struct resources {
    struct ibv_device_attr device_attr; /* Device attributes */
    struct ibv_port_attr port_attr;     /* IB port attributes */
    struct cm_con_data_t remote_props;  /* values to connect to remote side */
    struct ibv_context *ib_ctx;         /* device handle */
    struct ibv_pd *pd;                  /* PD handle */
    struct ibv_cq *cq;                  /* CQ handle */
    struct ibv_qp *qp;                  /* QP handle */

    struct ibv_mr *mr;                  /* MR handle for RDMA buf */
    struct ibv_mr *pi_mr[MAX_CRC_TASK_SIZE]; /* MR for protection information buffer */
    struct mlx5dv_mkey *sig_mkey[MAX_CRC_TASK_SIZE];

    int sock;                           /* TCP socket file descriptor */
};

struct config_t config = {
    .dev_name    = NULL,
    .server_name = NULL,
    .tcp_port    = 19875,
    .ib_port     = 1,
    .gid_idx     = 1
};

static
int sock_connect(const char *servername, int port)
{
    struct addrinfo *resolved_addr = NULL;
    struct addrinfo *iterator;
    char service[6];
    int sockfd = -1;
    int listenfd = 0;
    int tmp;

    struct addrinfo hints = {
        .ai_flags    = AI_PASSIVE,
        .ai_family   = AF_INET,
        .ai_socktype = SOCK_STREAM
    };

    if (sprintf(service, "%d", port) < 0) {
        goto sock_connect_exit;
    }

    /* Resovle DNS address, use sockfd as temp storage */
    if (getaddrinfo(servername, service, &hints, &resolved_addr) != 0) {
        err("%s for %s:%d\n", gai_strerror(sockfd), servername, port);
        goto sock_connect_exit;
    }

    /* Search through results and find the one we want */
    for (iterator = resolved_addr; iterator; iterator = iterator->ai_next) {
        sockfd = socket(iterator->ai_family, iterator->ai_socktype, iterator->ai_protocol);
    
        if (sockfd >=0) {
            if (servername) {
                /* Client mode. Initiate connection to remote */
                if ((tmp = connect(sockfd, iterator->ai_addr, iterator->ai_addrlen))) {
                    info("failed connect\n");
                    close(sockfd);
                    sockfd = -1;
                }
            } else {
                /* Server mode. Set up listening socket to accept a connection */
                listenfd = sockfd;
                sockfd = -1;
                if (bind(listenfd, iterator->ai_addr, iterator->ai_addrlen)) {
                    goto sock_connect_exit;
                }

                listen(listenfd, 1);
                sockfd = accept(listenfd, NULL, 0);
            }
        }
    }

sock_connect_exit:
    if (listenfd) {
        close(listenfd);
    }

    if (resolved_addr) {
        freeaddrinfo(resolved_addr);
    }

    if (sockfd > 0) goto out;

    if (servername) {
        err("Couldn't connect to %s:%d\n", servername, port);
    } else {
        err("server accept() failed\n");
    }

out:
    return sockfd;
}

/* Description:
 *  Sync data across a socket. The indicated local data will be sent to the
 *  remote. It will then wait for the remote to send its data back. It is
 *  assumed that the two sides are in sync and call this function in the proper
 *  order. Chaos will ensoure if they are not.
 *
 *  Also not this is a blocking function and wait for the full data to be
 *  received from the remote.
 */
int sock_sync_data(int sock, int xfer_size, const char *local_data, char *remote_data)
{
    int rc;
    int read_bytes = 0;
    int total_read_bytes = 0;

    rc = write(sock, local_data, xfer_size);
    if (rc < xfer_size) {
        err("Failed writing data during sock_sync_data\n");
    } else {
        rc = 0;
    }

    while (!rc && total_read_bytes < xfer_size) {
        read_bytes = read(sock, remote_data, xfer_size);
        if (read_bytes > 0) {
            total_read_bytes += read_bytes;
        } else {
            rc = read_bytes;
        }
    }

    return rc;
}

static
const char *wc_opcode_str(enum ibv_wc_opcode opcode)
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

static
int poll_cq_completion(struct ibv_cq *cq, enum ibv_wc_opcode expected)
{
    unsigned long start_time_msec;
    unsigned long cur_time_msec;
    struct timeval cur_time;
    struct ibv_wc wc = {};
    int poll_result;

    /* poll the completion for a while before giving up doing it .. */
    gettimeofday(&cur_time, NULL);
    start_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    do {
        poll_result = ibv_poll_cq(cq, 1, &wc);
        gettimeofday(&cur_time, NULL);
        cur_time_msec = (cur_time.tv_sec * 1000) + (cur_time.tv_usec / 1000);
    } while ((poll_result == 0) && ((cur_time_msec - start_time_msec) < MAX_POLL_CQ_TIMEOUT)); // poll CQ timeout 2s

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

    return 0;
}

static
void resources_init(struct resources *res)
{
    memset(res, 0, sizeof(*res));
    res->sock = -1;
}

static
int establish_oob_connect(struct resources *res)
{
    int rc = 0;

    if (config.server_name) {
        /* client side */
        res->sock = sock_connect(config.server_name, config.tcp_port);
        if (res->sock < 0) {
            err("failed to establish TCP connection to server %s, port %d\n",
                config.server_name, config.tcp_port);
            rc = -1;
        }
    } else {
        info("waiting on port %d for TCP connection\n", config.tcp_port);
        res->sock = sock_connect(NULL, config.tcp_port);
        if (res->sock < 0) {
            err("failed to establish TCP connection with client on port %d\n", config.tcp_port);
            rc = -1;
        }
    }

    return rc;
}

static
struct ibv_context* get_dev_ctx(void)
{
    int32_t dev_cnt = 0;
    struct ibv_device ** device_list = ibv_get_device_list(&dev_cnt);
    struct ibv_device *device = NULL;;

    /* must open device with DEVX */
    struct mlx5dv_context_attr attr = {.flags = MLX5DV_CONTEXT_FLAGS_DEVX};
    struct ibv_context *ctxt = NULL;

    if (device_list == NULL) {
        return NULL;
    }

    for (uint32_t idx = 0; idx < dev_cnt; idx++) {
        device = device_list[idx];

        if (!config.dev_name) {
            config.dev_name = strdup(ibv_get_device_name(device));
            info("device not specified, using first on found: %s\n", config.dev_name);
        }

        if (strcmp(config.dev_name, ibv_get_device_name(device)) == 0) {
            break;
        }
    }

    if (device == NULL) {
        goto out;
    }

    ctxt = mlx5dv_open_device(device, &attr);

out:
    ibv_free_device_list(device_list);

    return ctxt;
}

int check_support_crc32c(struct ibv_context *ctxt)
{
    struct mlx5dv_context dv_ctx = {};
    dv_ctx.comp_mask = MLX5DV_CONTEXT_MASK_SIGNATURE_OFFLOAD;

    if (!mlx5dv_is_supported(ctxt->device)) {
        err("device %s doesn't support DV\n", ibv_get_device_name(ctxt->device));
        return -1;
    }

    if (mlx5dv_query_device(ctxt, &dv_ctx) != 0 || !(dv_ctx.comp_mask & MLX5DV_CONTEXT_MASK_SIGNATURE_OFFLOAD)) {
        err("%s does not support signature offload\n", ibv_get_device_name(ctxt->device));
        return -1;
    }

    if (!(dv_ctx.sig_caps.crc_type & MLX5DV_SIG_CRC_TYPE_CAP_CRC32C)) {
        err("%s signature CRC32C offload isn't supported\n", ibv_get_device_name(ctxt->device));
        return -1;
    }

    return 0;
}

static
struct ibv_mr* alloc_mr(struct ibv_pd *pd, size_t size)
{
    int mr_flags = 0;
    if (config.server_name) {
        mr_flags = IBV_ACCESS_REMOTE_READ;
    } else {
        mr_flags = IBV_ACCESS_LOCAL_WRITE;
    }

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

static
void free_mr(struct ibv_mr **mr)
{
    void *ptr;

    if (!*mr) return;

    ptr = (*mr)->addr;
    int rst = ibv_dereg_mr(*mr);
    if (rst) {
        err("ibv_dereg_mr: %s\n", strerror(rst));
    } else {
        *mr = NULL;
    }

    free(ptr);
}

static
struct mlx5dv_mkey *create_sig_mkey(struct ibv_pd *pd)
{
    struct mlx5dv_mkey_init_attr mkey_attr = {};
    mkey_attr.pd = pd;
    mkey_attr.max_entries = 1;
    mkey_attr.create_flags = MLX5DV_MKEY_INIT_ATTR_FLAGS_INDIRECT | MLX5DV_MKEY_INIT_ATTR_FLAGS_BLOCK_SIGNATURE;
    struct mlx5dv_mkey *sig_mkey;

    sig_mkey = mlx5dv_create_mkey(&mkey_attr);
    if (!sig_mkey)
        err("mlx5dv_create_mkey: %s\n", strerror(errno));

    return sig_mkey;
}

static
void destroy_sig_mkey(struct mlx5dv_mkey **mkey)
{
    if (!*mkey) return;

    int rst = mlx5dv_destroy_mkey(*mkey);
    if (rst) {
        err("mlx5dv_destroy_mkey: %s\n", strerror(rst));
    } else {
        *mkey = NULL;
    }
}

static
int configure_sig_mkey(struct resources *res, int src_idx, struct mlx5dv_sig_block_attr *sig_attr)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
    struct mlx5dv_qp_ex *dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
    struct mlx5dv_mkey *mkey = res->sig_mkey[src_idx];
    struct mlx5dv_mkey_conf_attr conf_attr = {};
    uint32_t access_flags = IBV_ACCESS_LOCAL_WRITE;

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;

    mlx5dv_wr_mkey_configure(dv_qp, mkey, 3, &conf_attr);
    mlx5dv_wr_set_mkey_access_flags(dv_qp, access_flags);

    struct mlx5dv_mr_interleaved mr_interleaved[2];
    /* data */
    mr_interleaved[0].addr = (uintptr_t)res->mr->addr;
    mr_interleaved[0].bytes_count = CRC32C_BLOCK_SIZE;
    mr_interleaved[0].bytes_skip = 0;
    mr_interleaved[0].lkey = res->mr->lkey;
    /* protection */
    mr_interleaved[1].addr = (uintptr_t)res->pi_mr[src_idx]->addr;
    mr_interleaved[1].bytes_count = sizeof(uint32_t); // 4 bytes for crc32c result
    mr_interleaved[1].bytes_skip = 0;
    mr_interleaved[1].lkey = res->pi_mr[src_idx]->lkey;

    mlx5dv_wr_set_mkey_layout_interleaved(dv_qp, 1, 2, mr_interleaved);
    mlx5dv_wr_set_mkey_sig_block(dv_qp, sig_attr);

    return ibv_wr_complete(qpx);
}

enum sig_mode {
    SIG_MODE_INSERT_ON_MEM,
};

static
int reg_sig_mkey(struct resources *res, int src_idx, enum sig_mode mode)
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

        switch (CRC32C_BLOCK_SIZE) {
        case 4096:
            mem_domain.block_size = MLX5DV_BLOCK_SIZE_4096;
            break;
        default:
            err("this example only support block size 4096\n");
            return -1;
        }
        
        mem_domain.sig.crc = &crc_sig;
        break;
    default:
        err("this example doesn't verify wire date integrity\n");
        return -1;
    }

    struct mlx5dv_sig_block_attr sig_attr = {
        .mem = &mem_domain,
        .check_mask = MLX5DV_SIG_MASK_CRC32C,
    };

    if (configure_sig_mkey(res, src_idx, &sig_attr)) {
        err("Failed to request configure sig MKEY\n");
        return -1;
    }

    if (poll_cq_completion(res->qp->send_cq, IBV_WC_DRIVER1)) {
        err("Failed to complete configure sig MKEY\n");
        return -1;
    }

    return 0;
}

static
int inv_sig_mkey(struct resources *res, int src_idx)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(res->qp);
    int rc;

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_SIGNALED;
    ibv_wr_local_inv(qpx, res->sig_mkey[src_idx]->rkey);
    rc = ibv_wr_complete(qpx);
    if (rc) {
        err("Local invalidate sig MKEY: %s\n", strerror(rc));
        return -1;
    }

    if (poll_cq_completion(res->qp->send_cq, IBV_WC_LOCAL_INV)) {
        err("Failed to invalidete sig MKEY\n");
        return -1;
    }

    return rc;
}

static
int check_sig_mkey(struct mlx5dv_mkey *mkey)
{
    struct mlx5dv_mkey_err err_info;
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
        info("SIG ERROR: expected 0x%lx, actual 0x%lx, offset %lu\n",
             err_info.err.sig.expected_value,
             err_info.err.sig.actual_value, err_info.err.sig.offset);

    return sig_err;
}

static
struct ibv_qp* create_qp(struct ibv_context *ctxt, struct ibv_pd* pd, struct ibv_cq *rq_cq, struct ibv_cq *sq_cq)
{
    struct ibv_qp *qp;

    struct ibv_qp_cap qp_cap = {
        .max_send_wr = config.server_name == NULL ? (2U + MAX_CRC_TASK_SIZE) : 1,
        .max_send_sge = 1,
        .max_inline_data = config.server_name == NULL ? 512U : 0,
    };

    struct ibv_qp_init_attr_ex qp_attr = {
        .qp_context = NULL,
        .send_cq = sq_cq,
        .recv_cq = rq_cq,
        .cap = qp_cap,

        .qp_type = IBV_QPT_RC,
        .sq_sig_all = 0,
        .comp_mask = IBV_QP_INIT_ATTR_PD | (config.server_name == NULL ? (0U + IBV_QP_INIT_ATTR_SEND_OPS_FLAGS) : 0),
        .pd = pd,
        .send_ops_flags = config.server_name == NULL ? (0UL + IBV_QP_EX_WITH_RDMA_READ) : 0,
    };

    /* signature specific attributes */
    struct mlx5dv_qp_init_attr qp_dv_attr = {
        .comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS,
        .send_ops_flags = config.server_name == NULL ? (0UL + MLX5DV_QP_EX_WITH_MKEY_CONFIGURE) : 0,
    };

    qp = mlx5dv_create_qp(ctxt, &qp_attr, &qp_dv_attr);
    if (!qp)
        err("mlx5dv_create_qp: %s\n", strerror(errno));

    return qp;
}

static
int modify_qp_to_init(struct ibv_qp *qp)
{
    int mask = IBV_QP_STATE | IBV_QP_PORT | IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS;
    struct ibv_qp_attr qp_attr = {
        .qp_state = IBV_QPS_INIT,
        .qp_access_flags = config.server_name != NULL ? IBV_ACCESS_REMOTE_READ : IBV_ACCESS_LOCAL_WRITE,
        .pkey_index = 0,
        .port_num = config.ib_port,
    };

    if (ibv_modify_qp(qp, &qp_attr, mask)) {
        err("failed to modify qp:0x%x to init\n", qp->qp_num);
        return -1;
    }

    return 0;
}

static
int modify_qp_to_rtr(struct ibv_qp *qp, uint32_t remote_qpn, uint8_t *dgid)
{
    struct ibv_qp_attr qp_attr = {
        .qp_state = IBV_QPS_RTR,
        .path_mtu = IBV_MTU_4096,
        .rq_psn = 0,
        .dest_qp_num = remote_qpn,
        .ah_attr = {
            .grh = {
                .sgid_index = config.gid_idx,
                .hop_limit = 64
            },
            .is_global = 1,
            .port_num = config.ib_port 
        },
        .max_dest_rd_atomic = config.server_name != NULL ? ((uint8_t)MAX_CRC_TASK_SIZE) : (uint8_t)0,
        .min_rnr_timer = 0x12
    };
    memcpy(&qp_attr.ah_attr.grh.dgid, dgid, 16);

    int mask = IBV_QP_STATE | IBV_QP_AV | \
        IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | \
        IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    int rc = ibv_modify_qp(qp, &qp_attr, mask);
    if (rc) {
        err("failed to modify QP state to RTR\n");
    }

    return rc;
}

static
int modify_qp_to_rts(struct ibv_qp *qp)
{
    struct ibv_qp_attr qp_attr = {
        .qp_state  = IBV_QPS_RTS,
        .sq_psn    = 0,
        .max_rd_atomic = config.server_name == NULL ? (uint8_t)MAX_CRC_TASK_SIZE : (uint8_t)0,
        .timeout   = 0x12,
        .retry_cnt = 6,
        .rnr_retry = 0
    };

    int mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |\
        IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;

    int rc = ibv_modify_qp(qp, &qp_attr, mask);
    if (rc) {
        err("failed to modify QP state to RTS\n");
    }

    return rc;
}

static
int resources_destroy(struct resources *res)
{
    int rc = 0;

    if (res->qp && ibv_destroy_qp(res->qp)) {
        err("failed to destroy QP\n");
        rc = 1;
    }

    if (res->cq && ibv_destroy_cq(res->cq)) {
        err("failed to destroy CQ\n");
        rc = 1;
    }

    for (int i = 0; i < MAX_CRC_TASK_SIZE; i++) {
        destroy_sig_mkey(&res->sig_mkey[i]);
        free_mr(&res->pi_mr[i]);
    }

    if (res->mr) {
       free_mr(&res->mr);
    }

    if (res->pd && ibv_dealloc_pd(res->pd)) {
        err("failed to deallocate PD\n");
        rc = 1;
    }

    if (res->ib_ctx && ibv_close_device(res->ib_ctx)) {
        err("failed to close device context\n");
        rc = 1;
    }
    
    if (res->sock >= 0 && close(res->sock)) {
        err("failed to close socket\n");
        rc = 1;
    } else {
        res->sock = -1;
    }

    return rc;
}

static
int resources_create(struct resources *res)
{
    int rc = 0;

    rc = establish_oob_connect(res);
    if (rc) {
        rc = 1;
        goto resources_create_exit;
    }
    info("established OOB TCP connection\n");

    res->ib_ctx = get_dev_ctx();
    if (!res->ib_ctx) {
        err("failed to open device %s\n", config.dev_name);
        rc = 1;
        goto resources_create_exit;
    }

    if (config.server_name == NULL && check_support_crc32c(res->ib_ctx) != 0) {
        err("device:%s not support crc32c\n", config.dev_name);
        rc = 1;
        goto resources_create_exit;
    }

    /* query port properties */
    if (ibv_query_port(res->ib_ctx, config.ib_port, &res->port_attr) ||
        res->port_attr.state != IBV_PORT_ACTIVE ||
        res->port_attr.link_layer != IBV_LINK_LAYER_ETHERNET) {
        err("ibv_query_port on port %u failed\n", config.ib_port);
        rc = 1;
        goto resources_create_exit;
    }

    res->pd = ibv_alloc_pd(res->ib_ctx);
    if (!res->pd) {
        err("ibv_alloc_pd failed\n");
        rc = 1;
        goto resources_create_exit;
    }

    res->mr = alloc_mr(res->pd, CRC32C_BLOCK_SIZE);
    if (!res->mr) {
        err("ibv_reg_mr failed\n");
        rc = 1;
        goto resources_create_exit;
    }

    info("Local MR addr = %p, rkey = 0x%x, lkey = 0x%x\n",
         res->mr->addr, res->mr->rkey, res->mr->lkey);

    if (config.server_name == NULL) {
        for (int i = 0; i < MAX_CRC_TASK_SIZE; i++) {
            res->pi_mr[i] = alloc_mr(res->pd, 4);
            res->sig_mkey[i] = create_sig_mkey(res->pd);
        }
    }

    res->cq = ibv_create_cq(res->ib_ctx, CQ_SIZE, NULL, NULL, 0);
    if (!res->cq) {
        err("failed to create CQ with %u entries\n", CQ_SIZE);
        rc = 1;
        goto resources_create_exit;
    }

    res->qp = create_qp(res->ib_ctx, res->pd, res->cq, res->cq);
    if (res->qp == NULL) {
        err("failed to create QP\n");
        rc = 1;
        goto resources_create_exit;
    }
    if (modify_qp_to_init(res->qp) != 0) {
        err("failed to RST2INIT QP\n");
        rc = 1;
        goto resources_create_exit;
    }

    return 0;

resources_create_exit:
    resources_destroy(res);
    return -1;
}

static int connect_qp(struct resources *res)
{
    struct cm_con_data_t local_con_data;
    struct cm_con_data_t remote_con_data;
    struct cm_con_data_t tmp_con_data;
    int rc = 0;
    char temp_char;
    uint8_t *p = NULL;
    union ibv_gid my_gid;

    if (config.gid_idx >= 0) {
        rc = ibv_query_gid(res->ib_ctx, config.ib_port, config.gid_idx, &my_gid);
        if (rc) {
            err("could not get gid for port %d, index %d\n", config.ib_port, config.gid_idx);
            return rc;
        }
    }

    /* exchange using TCP sockets info required to connect QPs */
    local_con_data.addr = htonll((uintptr_t)res->mr->addr);
    local_con_data.rkey = htonl(res->mr->rkey);
    local_con_data.qp_num = htonl(res->qp->qp_num);
    memcpy(local_con_data.gid, &my_gid, 16);

    if (sock_sync_data(res->sock, sizeof(struct cm_con_data_t), (char*)&local_con_data, (char*)&tmp_con_data) < 0) {
        err("failed to exchange connection data between sides\n");
        rc = 1;
        goto connect_qp_exit;
    }

    remote_con_data.addr = ntohll(tmp_con_data.addr);
    remote_con_data.rkey = ntohl(tmp_con_data.rkey);
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
    memcpy(remote_con_data.gid, tmp_con_data.gid, 16);

    res->remote_props = remote_con_data;

    info("Remot MR addr = 0x%" PRIx64 ", rkey = 0x%x\n", remote_con_data.addr, remote_con_data.rkey);

    info("Remote QP number = 0x%x\n", remote_con_data.qp_num);
    p = remote_con_data.gid;
    info("Remote GID = %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
         p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);

    /* modify the QP to RTR */
    rc = modify_qp_to_rtr(res->qp, remote_con_data.qp_num, remote_con_data.gid);
    if (rc) {
        err("failed to modify QP state to RTR\n");
        goto connect_qp_exit;
    }
    info("QP state was changed to RTR\n");

    rc = modify_qp_to_rts(res->qp);
    if (rc) {
        err("failed to modify QP state to RTS\n");
        goto connect_qp_exit;
    }
    info("QP state was changed to RTS\n");

    /* sync to make sure that both sides are in states that they can connect
     * to prevent packet losse */
    if (sock_sync_data(res->sock, 1, "Q", &temp_char)) {
        /* just send a dummy char back and forth */
        err("sync error after QPs are were moved to RTS\n");
        rc = 1;
    }

connect_qp_exit:
    return rc;
}

static
void print_config(void)
{
    info("------------------------------\n");
    info("Device name :\"%s\"\n", config.dev_name);
    info("IB port     :%u\n", config.ib_port);

    if (config.server_name) {
        info("IP          :%s\n", config.server_name);
    }

    info("TCP port    :%u\n", config.tcp_port);
    if (config.gid_idx >= 0) {
        info("GID index   :%u\n", config.gid_idx);
    }
    info("------------------------------\n");
}

static
void usage(const char *argv0)
{
    info("Usage:\n");
    info(" %s start a server and wait for connection\n", argv0);
    info(" %s <host> connect to server at <host>\n", argv0);
    info("\n");
    info("Options:\n");
    info(" -p, --port <port> listen on/connect to port <port> (default 18515)\n");
    info(" -d, --ib-dev <dev> use IB device <dev> (default first device found)\n");
    info(" -i, --ib-port <port> use port <port> of IB device (default 1)\n");
    info(" -g, --gig_idx <gid index> gid index to be used in GRH(default not used)\n");
}

static
void parse_option(int argc, char *argv[])
{
    /* parse the command line parameters */
    while (1) {
        int c;

        static struct option long_options[] = {
            {.name = "port",    .has_arg = 1, .val = 'p'},
            {.name = "ib-dev",  .has_arg = 1, .val = 'd'},
            {.name = "ib-port", .has_arg = 1, .val = 'i'},
            {.name = "gid-idx", .has_arg = 1, .val = 'g'},
            {.name = NULL,      .has_arg = 0, .val = '\0'}
        };

        c = getopt_long(argc, argv, "p:d:i:g:", long_options, NULL);
        if (c == -1) {
            break;
        }

        switch(c) {
        case 'p':
            config.tcp_port = strtoul(optarg, NULL, 0);
            break;
        case 'd':
            config.dev_name = strdup(optarg);
            break;
        case 'i':
            config.ib_port = (uint8_t)strtoul(optarg, NULL, 0);
            if (config.ib_port < 0) {
                usage(argv[0]);
                exit(-1);
            }
            break;
        case 'g':
            config.gid_idx = (uint8_t)strtoul(optarg, NULL, 0);
            if (config.gid_idx < 0) {
                usage(argv[0]);
                exit(-1);
            }
            break;
        default:
            usage(argv[0]);
            exit(-1);
        }
    }
}
int main(int argc, char *argv[])
{
    struct resources res;
    struct ibv_qp_ex *qpx = NULL;
    int rc = 1;
    char temp_char;

    parse_option(argc, argv);
    if (optind == argc - 1) {
        config.server_name = argv[optind];
    } else if (optind < argc) {
        usage(argv[0]);
        return 1;
    }

    print_config();

    resources_init(&res);
    /* create resources before using them */
    if (resources_create(&res)) {
        err("failed to create resources\n");
        goto main_exit;
    }

    /* connect the QPs */
    if (connect_qp(&res)) {
        err("failed to connect QPs\n");
        goto main_exit;
    }

    if (config.server_name == NULL) {
        for (int i = 0; i < MAX_CRC_TASK_SIZE; i++) {
            reg_sig_mkey(&res, i, SIG_MODE_INSERT_ON_MEM);
        }

        qpx = ibv_qp_to_qp_ex(res.qp);
        ibv_wr_start(qpx);

        switch (MAX_CRC_TASK_SIZE) {
        case 16: qpx->wr_id = 16; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[15]->lkey, 0, CRC32C_BLOCK_SIZE);
        case 15: qpx->wr_id = 15; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[14]->lkey, 0, CRC32C_BLOCK_SIZE);
        case 14: qpx->wr_id = 14; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[13]->lkey, 0, CRC32C_BLOCK_SIZE);
        case 13: qpx->wr_id = 13; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[12]->lkey, 0, CRC32C_BLOCK_SIZE);
        case 12: qpx->wr_id = 12; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[11]->lkey, 0, CRC32C_BLOCK_SIZE);
        case 11: qpx->wr_id = 11; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[10]->lkey, 0, CRC32C_BLOCK_SIZE);
        case 10: qpx->wr_id = 10; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[9]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  9: qpx->wr_id =  9; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[8]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  8: qpx->wr_id =  8; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[7]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  7: qpx->wr_id =  7; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[6]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  6: qpx->wr_id =  6; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[5]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  5: qpx->wr_id =  5; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[4]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  4: qpx->wr_id =  4; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[3]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  3: qpx->wr_id =  3; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[2]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  2: qpx->wr_id =  2; qpx->wr_flags = 0;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[1]->lkey, 0, CRC32C_BLOCK_SIZE);
        case  1: qpx->wr_id =  1; qpx->wr_flags = IBV_SEND_SIGNALED;
            ibv_wr_rdma_read(qpx, res.remote_props.rkey, res.remote_props.addr);
            ibv_wr_set_sge(qpx, res.sig_mkey[0]->lkey, 0, CRC32C_BLOCK_SIZE);
        }

        if (ibv_wr_complete(qpx))
            err("failed to post RDMA_READ WRs\n");

        if (poll_cq_completion(res.qp->send_cq, IBV_WC_RDMA_READ))
            err("failed to complete RDMA_READ operaion\n");

        for (int i = 0; i < MAX_CRC_TASK_SIZE; i++) {
            if (check_sig_mkey(res.sig_mkey[i]) < 0) {
                err("failed to check sig_mkey\n");
            }
            inv_sig_mkey(&res, i);
        }
    }

    /* Sync so we are sure server side has data ready before client tries to read it */
    if (sock_sync_data(res.sock, 1, "R", &temp_char)) {
        /* just send a dummy char back and forth */
        err("sync error before RDMA ops\n");
        rc = 1;
        goto main_exit;
    }

    rc = 0;
    info("normal exit\n");

main_exit:
    if (resources_destroy(&res)) {
        err("failed to destroy resources\n");
        rc = 1;
    }

    if (config.dev_name) {
        free((char*)config.dev_name);
    }

    return rc;
}
