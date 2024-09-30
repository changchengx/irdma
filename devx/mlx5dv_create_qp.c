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
    uint32_t qp_num; /* QP number */
    uint16_t lid;    /* LID of the IB port */
    uint8_t gid[16]; /* gid */
}__attribute__((packed));

struct cm_con_data_t local_con_data, remote_con_data;

static void init_local_con_data(struct ibv_context* ctxt, struct ibv_qp *qp)
{
    struct ibv_port_attr port_attr = {};
    if (ibv_query_port(ctxt, 1, &port_attr)) {
        printf("failed to query qp:0x%06x port1 attr\n", qp->qp_num);
    }

    union ibv_gid local_gid = {};
    if (ibv_query_gid(ctxt, 1, 3, &local_gid)) {
        printf("failed to query qp:0x%06x port1 gid3\n", qp->qp_num);
    }

    local_con_data.addr = htonll((uintptr_t)data_chunk);
    local_con_data.rkey = htonl(mr->rkey);
    local_con_data.qp_num = htonl(qp->qp_num);
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
    remote_con_data.qp_num = ntohl(tmp_con_data.qp_num);
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

static void modify_dv_qp_rst2init(struct ibv_qp *qp)
{
    struct ibv_qp_attr qp_attr = {};

    qp_attr.qp_state  = IBV_QPS_INIT;
    qp_attr.port_num  = 1;
    qp_attr.pkey_index   = 0;
    qp_attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE  | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    if (ibv_modify_qp(qp, &qp_attr, IBV_QP_STATE | IBV_QP_PORT | IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS)) {
        printf("failed to modify qp:0x%06x rst2init\n", qp->qp_num);
    } else {
        printf("success modify qp:0x%06x rst2init\n", qp->qp_num);
    }
}

static int modify_qp_init2rtr(struct ibv_qp *qp)
{
    struct ibv_qp_attr qp_attr = {};
    int qp_attr_mask;
    int rc;

    qp_attr.qp_state = IBV_QPS_RTR;
    qp_attr.path_mtu = IBV_MTU_1024;

    qp_attr.dest_qp_num = remote_con_data.qp_num;
    qp_attr.rq_psn = 0;
    qp_attr.max_dest_rd_atomic = 1;
    qp_attr.min_rnr_timer = 0x12;

    qp_attr.ah_attr.dlid = remote_con_data.lid;
    qp_attr.ah_attr.sl = 0;
    qp_attr.ah_attr.src_path_bits = 0;
    qp_attr.ah_attr.port_num = 1;

    qp_attr.ah_attr.is_global = 1;
    qp_attr.ah_attr.grh.sgid_index = 3;
    memcpy(&qp_attr.ah_attr.grh.dgid, remote_con_data.gid, 16);
    qp_attr.ah_attr.grh.flow_label = 0;
    qp_attr.ah_attr.grh.hop_limit = 1;
    qp_attr.ah_attr.grh.traffic_class = 0;

    qp_attr_mask = IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER;

    rc = ibv_modify_qp(qp, &qp_attr, qp_attr_mask);
    if (rc) {
        printf("failed to modify qp:0x%06x init2rts\n", qp->qp_num);
    } else {
        printf("success modify qp:0x%06x init2rtr\n", qp->qp_num);
    }

    return rc;
}

static int modify_qp_rtr2rts(struct ibv_qp *qp)
{
    struct ibv_qp_attr qp_attr = {};
    int qp_attr_mask;
    int rc;

    qp_attr.qp_state = IBV_QPS_RTS;
    qp_attr.sq_psn = 0;
    qp_attr.timeout = 0x12;
    qp_attr.rnr_retry = 0;
    qp_attr.retry_cnt = 6;
    qp_attr.max_rd_atomic = 1;

    qp_attr_mask = IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC;
    rc = ibv_modify_qp(qp, &qp_attr, qp_attr_mask);
    if (rc) {
        printf("failed to modify qp:0x%06x rtr2rts\n", qp->qp_num);
    } else {
        printf("success modify qp:0x%06x rtr2rts\n", qp->qp_num);
    }

    return rc;
}

void post_rdma_write_write_imm(struct ibv_qp* qp)
{
    data_chunk[0] = 0; data_chunk[1] = 0;
    data_chunk[server] = server ? 'S' : 'C';

    if (server) {
        struct ibv_recv_wr rr = {};

        // RQ.WQE.sg_list could be NULL if only to get ibv_wc.wr_id when verifying RDMA_WRITE_WITH_IMM
        // Here, we also verify the RQ generated CQE's wr_id, so rr.sg_list isn't NULL and rr.num_sge isn't 0
        struct ibv_sge sge = {};
        sge.length = sizeof(uint32_t);
        sge.lkey = mr->lkey;
        sge.addr = (uint64_t)data_chunk + 0x64;
        rr.sg_list = &sge;
        rr.num_sge = 1;

        rr.next = NULL;
        rr.wr_id = 0xdeadbeef;

        struct ibv_recv_wr *bad_wr = NULL;
        if (ibv_post_recv(qp, &rr, &bad_wr)) {
            printf("failed to post RR\n");
        } else {
            printf("post RR to server\n");
        }
        sync_fence();
    } else {
        sync_fence();
        struct ibv_send_wr sr = {};
        struct ibv_sge sge = {};

        sge.length = sizeof(uint32_t);
        sge.lkey = mr->lkey;
        sge.addr = (uint64_t)data_chunk + server * sizeof(uint32_t);

        sr.next = NULL;
        sr.sg_list = &sge;
        sr.num_sge = 1;
        sr.opcode = IBV_WR_RDMA_WRITE_WITH_IMM;
        sr.send_flags = IBV_SEND_SIGNALED;
        sr.wr_id = 0xdeadbeef;
        sr.imm_data = 0xcafebeef;
        sr.wr.rdma.remote_addr = remote_con_data.addr + server * sizeof(uint32_t);
        sr.wr.rdma.rkey = remote_con_data.rkey;

        struct ibv_send_wr *bad_wr = NULL;
        if (ibv_post_send(qp, &sr, &bad_wr)) {
            printf("failed to post SQ WQE RDMA_WRITE_WITH_IMM\n");
        }
    }
    sync_fence();

    struct ibv_wc wc = {};

    if (server) {
        while (ibv_poll_cq(qp->recv_cq, 1, &wc) != 1) continue;

        if (wc.status == IBV_WC_SUCCESS && data_chunk[!server] == 'C' && wc.imm_data == 0xcafebeef & wc.wr_id == 0xdeadbeef) {
            printf("server pass RDMA_WRITE_WITH_IMM test\n");
        } else {
            printf("server get unexpected data ==> %c & 0x%08x & 0x%08x\n", data_chunk[!server], wc.imm_data, wc.wr_id);
        }
    } else {
        while (ibv_poll_cq(qp->send_cq, 1, &wc) != 1) continue;

        if (wc.status == IBV_WC_SUCCESS && wc.wr_id == 0xdeadbeef) {
            printf("client pass RDMA_WRITE_WITH_IMM test\n");
        } else {
            printf("client failed at RDMA_WRITE_WITH_IMM\n");
        }
    }
}

void post_rdma_write(struct ibv_qp* qp)
{
    data_chunk[0] = 0; data_chunk[1] = 0;
    data_chunk[server] = server ? 'S' : 'C';

    sync_fence();
    ibv_wr_start(ibv_qp_to_qp_ex(qp));
    ibv_wr_rdma_write(ibv_qp_to_qp_ex(qp), remote_con_data.rkey, remote_con_data.addr + server * sizeof(uint32_t));
    ibv_wr_set_sge(ibv_qp_to_qp_ex(qp), mr->lkey, (uint64_t)data_chunk + server * sizeof(uint32_t), sizeof(uint32_t));
    if(ibv_wr_complete(ibv_qp_to_qp_ex(qp))) {
        printf("failed to post SQ WQE RDMA_WRITE\n");
    }
    sync_fence();

    if (data_chunk[!server] == server ? 'C' : 'S') {
        printf("pass RDMA_WRITE test\n");
    } else {
        printf("failed at RDMA_WRITE test\n");
    }
}

int main(int argc, char *argv[])
{
    char *dev_name = strdup(argv[1]);

    struct ibv_device *dev = get_device(dev_name);
    struct ibv_context *ctxt = ibv_open_device(dev);
    struct ibv_pd *pd = ibv_alloc_pd(ctxt);
    struct ibv_cq *cq = ibv_create_cq(ctxt, 16, NULL, NULL, 0);

    create_one_mr(pd);

    struct mlx5dv_qp_init_attr dv_attr = {};
    dv_attr.comp_mask = MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS;
#ifndef DEVX
    dv_attr.create_flags = MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE;
#else
    dv_attr.create_flags = MLX5DV_QP_CREATE_DISABLE_SCATTER_TO_CQE | MLX5DV_QP_CREATE_RC_DEVX;
#endif

    struct ibv_qp_init_attr_ex init_attr_ex = {};
    init_attr_ex.send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_RDMA_WRITE_WITH_IMM;
    init_attr_ex.pd = pd;
    init_attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS;

    init_attr_ex.qp_type = IBV_QPT_RC;

    init_attr_ex.send_cq = cq;
    init_attr_ex.recv_cq = cq;

    init_attr_ex.cap.max_inline_data = 8;
    init_attr_ex.cap.max_send_wr = 2;
    init_attr_ex.cap.max_recv_wr = 2;
    init_attr_ex.cap.max_send_sge = 1;
    init_attr_ex.cap.max_recv_sge = 1;

    struct ibv_qp *qp = mlx5dv_create_qp(ctxt, &init_attr_ex, &dv_attr);
    modify_dv_qp_rst2init(qp);

    if (qp) {
        printf("create qp with qpn:0x%06x\n", qp->qp_num);
    } else {
        printf("failed to create qp\n");
    }

    if (argc == 3) {
        server = 0;
        socket_fd = sock_connect(argv[2], 8976);
        printf("client: socket_fd = %d\n", socket_fd);
    } else {
        server = 1;
        socket_fd = sock_connect(NULL, 8976);
        printf("server: socket_fd = %d\n", socket_fd);
    }

    init_local_con_data(ctxt, qp);

    get_remote_con_data();
    printf("local_qpn:0x%06x, remote_qpn:0x%06x, local data:%p, local rkey:0x%08x, remote data:%p, remote rkey:0x%08x\n",
            local_con_data.qp_num, remote_con_data.qp_num, data_chunk, mr->rkey, (void*)(remote_con_data.addr), remote_con_data.rkey);

    modify_qp_init2rtr(qp);

    modify_qp_rtr2rts(qp);

    printf("\ntest RDMA_WRITE\n");
    post_rdma_write(qp);

    printf("\ntest RDMA_WRITE_WITH_IMM\n");
    post_rdma_write_write_imm(qp);

    return 0;
}
