/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */
// gcc hop_limit.c -libverbs -o hop_limit

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <infiniband/verbs.h>

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

struct ibv_cq* create_coredirect_cq(struct ibv_context* ctx, int cqe)
{
	return ibv_create_cq(ctx, cqe, NULL, NULL, 0);
}

struct ibv_qp* create_coredirect_master_qp(struct ibv_pd* pd, struct ibv_context *ctx, struct ibv_cq *cq, uint16_t send_wq_size)
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
    init_attr_ex.comp_mask = IBV_QP_INIT_ATTR_PD;
    mq = ibv_create_qp_ex(ctx, &init_attr_ex);

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
    attr.ah_attr.grh.hop_limit = 0x1;
    attr.ah_attr.grh.sgid_index = 3;
    attr.ah_attr.dlid = 0;
    attr.ah_attr.sl = 0;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = 1;

    if (ibv_query_gid(ctx, 1, 3, &gid)) {
        printf("can't read sgid of index %d\n", 3);
    }

    attr.ah_attr.grh.dgid = gid;

    rc = ibv_modify_qp(mq, &attr, IBV_QP_STATE | IBV_QP_AV | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN |
                                   IBV_QP_RQ_PSN | IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER);

    if (rc != 0) {
        printf("failed to modify management qp into rtr\n");
    }

    attr.qp_state = IBV_QPS_RTS;
    attr.timeout = 10;
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

int main(int argc, char *argv[])
{
    char *dev_name = strdup(argv[1]);

    struct ibv_device *dev = get_device(dev_name);
    struct ibv_context *ctx = ibv_open_device(dev);
    struct ibv_pd *pd = ibv_alloc_pd(ctx);

    struct ibv_cq *mcq = ibv_create_cq(ctx, 1, NULL, NULL, 0);
    struct ibv_qp *mqp = create_coredirect_master_qp(pd, ctx, mcq, 1);
    printf("mqpn:0x%06x\n", mqp->qp_num);

    while(1);

    return 0;
}
