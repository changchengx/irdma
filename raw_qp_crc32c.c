/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

/* Build:
 * $ gcc -o raw_qp_crc raw_qp_crc32c.c -libverbs
 *
 * Server env:
 * | $ show_gids | grep mlx5_0 | grep v2 |  grep '\<3\>'
 * | DEV  PORT INDEX GID                                  IPv4       VER DEV
 * | --   ---  ----  ---                                ---------    --- ---
 * | mlx5_0  1 3 0000:0000:0000:0000:0000:ffff:c0a8:210f 192.168.33.15 v2 enp6s0f0np0
 *
 * | $ ip a s enp6s0f0np0 | grep 'ether \|inet '
 * |     link/ether a0:88:c2:f5:dd:1a brd ff:ff:ff:ff:ff:ff
 * |     inet 192.168.33.15/24 brd 192.168.33.255 scope global enp6s0f0np0
 *
 * Client env:
 * | $ show_gids | grep mlx5_6 | grep v2 |  grep '\<3\>'
 * | DEV  PORT INDEX GID                                  IPv4       VER DEV
 * | --   ---  ----  ---                                ---------    --- ---
 * | mlx5_6  1 3 0000:0000:0000:0000:0000:ffff:c0a8:2111 192.168.33.17 v2 p7p1
 *
 * | $ ip a s p7p1 | grep 'ether \|inet '
 * |  link/ether a0:88:c2:f5:ee:9e brd ff:ff:ff:ff:ff:ff
 * |  inet 192.168.33.17/24 brd 192.168.33.255 scope global p7p1
 *
 * Run:
 *  Server
 *   $ sudo ./raw_qp_crc --port=20258 --ib-dev=mlx5_0 --local_mac a0:88:c2:f5:dd:1a --remote_mac a0:88:c2:f5:ee:9e --local_ip 192.168.33.15 --remote_ip 192.168.33.17 --local_port 8976 --remote_port 6789 --server
 *
 *  Client
 *   $ sudo ./raw_qp_crc --port=20258 --ib-dev=mlx5_6 --local_mac a0:88:c2:f5:ee:9e --remote_mac a0:88:c2:f5:dd:1a --local_ip 192.168.33.17 --remote_ip 192.168.33.15 --local_port 6789 --remote_port 8976 --client
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <endian.h>

#include <unistd.h>
#include <getopt.h>
#include <sys/time.h>

#include <arpa/inet.h>

#include <infiniband/verbs.h>
#include <infiniband/mlx5dv.h>

#include "crc32c.h"

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#define htobe32_const(x) (((x) >> 24) | (((x) >> 8) & 0xff00) | \
    ((((x) & 0xffffff) << 8) & 0xff0000) | ((((x) & 0xff) << 24) & 0xff000000))

#elif __BYTE_ORDER == __BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#define htobe32_const(x) (x)

#else
#error __BYTE_ORDER is neither __LITTLEN_ENDIAN nor __BIG_ENDIAN
#endif

#define info(format, arg...) fprintf(stdout, format, ##arg)
#define err(format, arg...) fprintf(stderr, "ERROR: " format, ##arg)

struct raw_ethernet_info {
    uint8_t  mac[6];
    uint32_t ip;
    int port;
};

struct eth_header {
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint16_t eth_type;
} __attribute__((packed));

struct IP_V4_header {
    #if defined(__LITTLE_ENDIAN_BITFIELD)
    uint8_t     ihl:4;
    uint8_t     version:4;
    #elif defined(__BIG_ENDIAN_BITFIELD)
    uint8_t     version:4;
    uint8_t     ihl:4;
    #else
    bug
    #endif
    uint8_t     tos;
    uint16_t    tot_len;
    uint16_t    id;
    uint16_t    frag_off;
    uint8_t     ttl;
    uint8_t     protocol;
    uint16_t    check;
    uint32_t    saddr;
    uint32_t    daddr;
}__attribute__((packed));

union IP_V4_header_raw {
    struct      IP_V4_header ip_header;
    uint32_t    raw[sizeof(struct IP_V4_header) / 4];
};

struct UDP_header {
    u_short uh_sport;   /* source port */
    u_short uh_dport;   /* destination port */
    u_short uh_ulen;    /* udp length */
    u_short uh_sum;     /* udp checksum */
}__attribute__((packed));

struct tc_params {
    int port;
    char *ib_devname;
    int gid_idx;

    uint8_t local_mac[6];
    uint8_t source_mac[6];
    int is_srce_mac;

    uint8_t remote_mac[6];
    uint8_t dest_mac[6];
    int is_dest_mac;

    uint32_t local_ip;
    int is_client_ip;

    uint32_t remote_ip;
    int is_server_ip;

    int server_port;
    int is_server_port;

    int client_port;
    int is_client_port;

    int is_ethertype;
    int ethertype;

    uint32_t client_ip;
    uint32_t server_ip;

    int local_port;
    int remote_port;

    int machine; // 1: server, 0: client

    int buff_size;
};

struct pingpong_context {
    struct tc_params *param;
    struct ibv_context *ctxt;
    struct ibv_pd *pd;

    char *buf;
    struct ibv_mr *mr;

    struct ibv_cq *send_cq;
    struct ibv_cq *recv_cq;

    struct ibv_qp* qp;

    struct ibv_qp* helper_qp; // help to to generate sig & umr mkey
    struct ibv_cq *helper_cq;
    struct ibv_mr *pi_mr;
    struct mlx5dv_mkey *sig_mkey;
};

int calc_flow_rules_size(void)
{
    int tot_size = sizeof(struct ibv_flow_attr);

    tot_size += sizeof(struct ibv_flow_spec_eth);
    tot_size += sizeof(struct ibv_flow_spec_ipv4_ext);
    tot_size += sizeof(struct ibv_flow_spec_tcp_udp);

    return tot_size;
}

int set_up_flow_rule(struct ibv_flow_attr **flow_rule, struct tc_params *param,
                      int local_port, int remote_port)
{
    int flow_rules_size = calc_flow_rules_size();
    void *header_buff = calloc(1, flow_rules_size);

    *flow_rule = (struct ibv_flow_attr*)header_buff;

    struct ibv_flow_attr *attr_info = (struct ibv_flow_attr*)header_buff;
    attr_info->size = flow_rules_size;
    attr_info->priority = 0;
    attr_info->num_of_specs = 1 + 1 + 1;
    attr_info->port = 1;
    attr_info->flags = 0;
    attr_info->type = IBV_FLOW_ATTR_NORMAL;

    header_buff = header_buff + sizeof(struct ibv_flow_attr);
    struct ibv_flow_spec* spec_info = (struct ibv_flow_spec*)header_buff;
    spec_info->eth.type = IBV_FLOW_SPEC_ETH;
    spec_info->eth.size = sizeof(struct ibv_flow_spec_eth);
    spec_info->eth.val.ether_type = 0;

    memcpy(spec_info->eth.val.dst_mac, param->source_mac, sizeof(param->source_mac));
    memset(spec_info->eth.mask.dst_mac, 0xFF, sizeof(spec_info->eth.mask.dst_mac));

    header_buff = header_buff + sizeof(struct ibv_flow_spec_eth);
    spec_info = (struct ibv_flow_spec*)header_buff;
    spec_info->ipv4.type = IBV_FLOW_SPEC_IPV4_EXT;
    spec_info->ipv4.size = sizeof(struct ibv_flow_spec_ipv4_ext);

    struct ibv_flow_spec_ipv4_ext *ipv4_spec = &spec_info->ipv4_ext;
    if (param->machine == 1) {
        ipv4_spec->val.dst_ip = param->server_ip;
        ipv4_spec->val.src_ip = param->client_ip;
        memset((void*)&ipv4_spec->mask.dst_ip, 0xFF, sizeof(ipv4_spec->mask.dst_ip));
        memset((void*)&ipv4_spec->mask.src_ip, 0xFF, sizeof(ipv4_spec->mask.src_ip));
    }

    header_buff = header_buff + sizeof(struct ibv_flow_spec_ipv4_ext);
    spec_info = (struct ibv_flow_spec*)header_buff;
    spec_info->tcp_udp.type = IBV_FLOW_SPEC_UDP;
    spec_info->tcp_udp.size = sizeof(struct ibv_flow_spec_tcp_udp);

    if (param->machine == 1) {
        spec_info->tcp_udp.val.dst_port = htons(local_port);
        spec_info->tcp_udp.val.src_port = htons(remote_port);
    } else {
        spec_info->tcp_udp.val.dst_port = htons(remote_port);
        spec_info->tcp_udp.val.src_port = htons(local_port);
    }

    memset((void*)&spec_info->tcp_udp.mask.dst_port, 0xFF, sizeof(spec_info->tcp_udp.mask.dst_port));
    memset((void*)&spec_info->tcp_udp.mask.src_port, 0xFF, sizeof(spec_info->tcp_udp.mask.src_port));

    if (param->is_ethertype) {
        spec_info->eth.val.ether_type = htons(param->ethertype);
        spec_info->eth.mask.ether_type = 0xffff;
    }

    return 0;
}

#define MAC_LEN (17)
#define ETHERTYPE_LEN (6)
#define MAC_ARR_LEN (6)
#define HEX_BASE (16)
static int parse_mac_from_str(char *mac, uint8_t *addr)
{
    char tmpMac[MAC_LEN+1];
    char *tmpField;
    int fieldNum = 0;

    if (strlen(mac) != MAC_LEN) {
        fprintf(stderr, "invalid MAC length\n");
        return -1;
    }
    if (addr == NULL) {
        fprintf(stderr, "invalid  output addr array\n");
        return -1;
    }

    strcpy(tmpMac, mac);
    tmpField = strtok(tmpMac, ":");
    while (tmpField != NULL && fieldNum < MAC_ARR_LEN) {
        char *chk;
        int tmpVal;
        tmpVal = strtoul(tmpField, &chk, HEX_BASE);
        if (tmpVal > 0xff) {
            fprintf(stderr, "field %d value %X out of range\n", fieldNum, tmpVal);
            return -1;
        }
        if (*chk != 0) {
            fprintf(stderr, "Non-digit character %c (%0x) detected in field %d\n", *chk, *chk, fieldNum);
            return -1;
        }
        addr[fieldNum++] = (u_int8_t) tmpVal;
        tmpField = strtok(NULL, ":");
    }
    if (tmpField != NULL || fieldNum != MAC_ARR_LEN) {
        fprintf(stderr, "MAC address longer than six fields\n");
        return -1;
    }
    return 0;
}

static void init_tc_params(struct tc_params *param)
{
    memset(param, 0, sizeof(*param));
    param->port = 18515;
    param->buff_size = 512; //554;
}

int parser(struct tc_params *param, char *argv[], int argc)
{
    static int local_mac_flag = 0;
    static int remote_mac_flag = 0;

    static int remote_ip_flag = 0;
    static int local_ip_flag = 0;

    static int local_port_flag = 0;
    static int remote_port_flag = 0;

    init_tc_params(param);

    static const struct option long_options[] = {
        { .name = "port",        .has_arg = 1, .val = 'p' },
        { .name = "ib-dev",      .has_arg = 1, .val = 'd' },

        { .name = "remote_mac",  .has_arg = 1, .flag = &remote_mac_flag, .val = 1 },
        { .name = "local_mac",   .has_arg = 1, .flag = &local_mac_flag, .val = 1 },

        { .name = "remote_ip",   .has_arg = 1, .flag = &remote_ip_flag, .val = 1 },
        { .name = "local_ip",    .has_arg = 1, .flag = &local_ip_flag, .val = 1 },

        { .name = "remote_port", .has_arg = 1, .flag = &remote_port_flag, .val = 1 },
        { .name = "local_port",  .has_arg = 1, .flag = &local_port_flag, .val = 1 },

        { .name = "ethertype",   .has_arg = 1, .val = 'Y' },

        { .name = "server",      .has_arg = 0, .val = 'Z' },
        { .name = "client",      .has_arg = 0, .val = 'P' },

        { .name = "size",        .has_arg = 1, .val = 's' },
    };

    int c, size_len;
    while (1) {
        int long_option_index = -1;
        c = getopt_long(argc, argv, "p:s:d:Y:ZP", long_options, &long_option_index);

        if (c == -1) break;

        switch (c) {
        case 'p': param->port = strtol(optarg, NULL, 0); break;

        case 'd': param->ib_devname = strdup(optarg); break;

        case 'Y': param->is_ethertype = 1;
                  param->ethertype = strtol(optarg, NULL, HEX_BASE);
                  break;

        case 'Z': param->machine = 1; break; // this is server
        case 'P': param->machine = 0; break; // this is client

        case 's': param->buff_size = strtol(optarg, NULL, 0); break;

        case 0: /* required for long options to work */
            if (remote_mac_flag) {
                param->is_dest_mac = 1;
                parse_mac_from_str(optarg, param->remote_mac);
                memcpy(param->dest_mac, param->remote_mac, MAC_ARR_LEN);
                remote_mac_flag = 0;
            }

            if (local_mac_flag) {
                param->is_srce_mac = 1;
                parse_mac_from_str(optarg, param->local_mac);
                memcpy(param->source_mac, param->local_mac, MAC_ARR_LEN);
                local_mac_flag = 0;
            }

            if (remote_ip_flag) {
                param->is_client_ip = 1;
                inet_pton(AF_INET, optarg, &param->remote_ip);
                remote_ip_flag = 0;
            }

            if (local_ip_flag) {
                param->is_server_ip = 1;
                inet_pton(AF_INET, optarg, &param->local_ip);
                local_ip_flag = 0;
            }

            if (remote_port_flag) {
                param->is_client_port = 1;
                param->remote_port = strtol(optarg, NULL, 0); break;
                remote_port_flag = 0;
            }

            if (local_port_flag) {
                param->is_server_port = 1;
                param->local_port = strtol(optarg, NULL, 0); break;
                local_port_flag = 0;
            }
        }
    }

    if (param->machine == 1) { // server side
        param->server_ip = param->local_ip;
        param->client_ip = param->remote_ip;
        param->server_port = param->local_port;
        param->client_port = param->remote_port;
    }

    if (param->machine == 0) { // client side
        param->server_ip = param->remote_ip;
        param->client_ip = param->local_ip;
        param->server_port = param->remote_port;
        param->client_port = param->local_port;
    }

    return 0;
}

struct ibv_context* get_dev_ctx(const char* dev_name)
{
    uint32_t dev_cnt = 0;
    struct ibv_device ** device_list = ibv_get_device_list(&dev_cnt);
    struct ibv_device *device = NULL;;

    if (device_list == NULL) {
        return NULL;
    }

    uint32_t idx = 0;
    for (idx = 0; idx < dev_cnt; idx++) {
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

void print_spec(struct ibv_flow_attr* flow_rule, struct tc_params* param)
{
    if (flow_rule == NULL) {
        printf("error : spec is NULL\n");
        return;
    }

    void* header_buff = (void*)flow_rule;
    header_buff = header_buff + sizeof(struct ibv_flow_attr);

    struct ibv_flow_spec* spec_info = (struct ibv_flow_spec*)header_buff;

    printf("MAC attached  : %02X:%02X:%02X:%02X:%02X:%02X\n",
            spec_info->eth.val.dst_mac[0],
            spec_info->eth.val.dst_mac[1],
            spec_info->eth.val.dst_mac[2],
            spec_info->eth.val.dst_mac[3],
            spec_info->eth.val.dst_mac[4],
            spec_info->eth.val.dst_mac[5]);

    if (param->is_server_ip && param->is_client_ip) {
        header_buff = header_buff + sizeof(struct ibv_flow_spec_eth);
        spec_info = (struct ibv_flow_spec*)header_buff;

        char str_ip_s[INET_ADDRSTRLEN] = {0};
        uint32_t src_ip = spec_info->ipv4.val.src_ip;
        inet_ntop(AF_INET, &src_ip, str_ip_s, INET_ADDRSTRLEN);
        printf("spec_info - src_ip   : %s\n",str_ip_s);

        char str_ip_d[INET_ADDRSTRLEN] = {0};
        uint32_t dst_ip = spec_info->ipv4.val.dst_ip;
        inet_ntop(AF_INET, &dst_ip, str_ip_d, INET_ADDRSTRLEN);
        printf("spec_info - dst_ip   : %s\n",str_ip_d);
    }

    if (param->is_server_port && param->is_client_port) {
        int ip_size = sizeof(struct ibv_flow_spec_ipv4_ext);

        header_buff = header_buff + ip_size;
        spec_info = header_buff;
        printf("spec_info - dst_port : %d\n",ntohs(spec_info->tcp_udp.val.dst_port));
        printf("spec_info - src_port : %d\n",ntohs(spec_info->tcp_udp.val.src_port));
    }
}

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

static int configure_sig_mkey(struct pingpong_context *ctx, struct mlx5dv_sig_block_attr *sig_attr)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(ctx->helper_qp);
    struct mlx5dv_qp_ex *dv_qp = mlx5dv_qp_ex_from_ibv_qp_ex(qpx);
    struct mlx5dv_mkey *mkey = ctx->sig_mkey;
    struct mlx5dv_mkey_conf_attr conf_attr = {};
    uint32_t access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_SIGNALED | IBV_SEND_INLINE;

    mlx5dv_wr_mkey_configure(dv_qp, mkey, 3, &conf_attr);
    mlx5dv_wr_set_mkey_access_flags(dv_qp, access_flags);

    struct mlx5dv_mr_interleaved mr_interleaved[2];
    /* data */
    mr_interleaved[0].addr = (uintptr_t)ctx->mr->addr;
    mr_interleaved[0].bytes_count = 512;
    mr_interleaved[0].bytes_skip = 0;
    mr_interleaved[0].lkey = ctx->mr->lkey;
    /* protection */
    mr_interleaved[1].addr = (uintptr_t)ctx->pi_mr->addr;
    mr_interleaved[1].bytes_count = sizeof(uint32_t); // 4 bytes for crc32c result
    mr_interleaved[1].bytes_skip = 0;
    mr_interleaved[1].lkey = ctx->pi_mr->lkey;

    mlx5dv_wr_set_mkey_layout_interleaved(dv_qp, 1, 2, mr_interleaved);
    mlx5dv_wr_set_mkey_sig_block(dv_qp, sig_attr);

    return ibv_wr_complete(qpx);
}

enum sig_mode {
    SIG_MODE_INSERT_ON_MEM,
};

static int reg_sig_mkey(struct pingpong_context *ctx, enum sig_mode mode)
{
    struct mlx5dv_sig_crc crc_sig;
    struct mlx5dv_sig_block_domain mem_domain;

    switch (mode) {
    case SIG_MODE_INSERT_ON_MEM:
        memset(&crc_sig, 0, sizeof(crc_sig));
        crc_sig.type = MLX5DV_SIG_CRC_TYPE_CRC32C;
        crc_sig.seed = 0xffffffffU;

        memset(&mem_domain, 0, sizeof(mem_domain));
        mem_domain.sig_type = MLX5DV_SIG_TYPE_CRC;
        mem_domain.block_size = MLX5DV_BLOCK_SIZE_512;
        mem_domain.sig.crc = &crc_sig;
        break;
    default:
        break;
    }

    struct mlx5dv_sig_block_attr sig_attr = {
        .mem = &mem_domain,
        .check_mask = MLX5DV_SIG_MASK_CRC32C,
    };

    if (configure_sig_mkey(ctx, &sig_attr))
        return -1;

    info("Post mkey configure WR, opcode DRIVER1\n");

    if (poll_completion(ctx->helper_qp->send_cq, IBV_WC_DRIVER1)) {
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

static int inv_sig_mkey(struct pingpong_context *ctx)
{
    struct ibv_qp_ex *qpx = ibv_qp_to_qp_ex(ctx->helper_qp);
    int rc;

    ibv_wr_start(qpx);
    qpx->wr_id = 0;
    qpx->wr_flags = IBV_SEND_SIGNALED;
    ibv_wr_local_inv(qpx, ctx->sig_mkey->rkey);
    rc = ibv_wr_complete(qpx);
    if (rc) {
        err("Local invalidate sig MKEY: %s\n", strerror(rc));
        return -1;
    }

    if (poll_completion(ctx->helper_qp->send_cq, IBV_WC_LOCAL_INV)) {
        err("Failed to invalidete sig MKEY\n");
        return -1;
    }

    info("Sig MKEY is invalidated\n");

    return rc;
}

int ctx_modify_qp_to_init(struct pingpong_context *ctx)
{
    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));

    int flags = IBV_QP_STATE | IBV_QP_PORT; // no need to set IBV_QP_PKEY_INDEX
    attr.qp_state = IBV_QPS_INIT;
    attr.pkey_index = 0;
    attr.port_num = 1;

    if (ibv_modify_qp(ctx->qp, &attr, flags)) {
        fprintf(stderr, "Failed to modify QP to INIT\n");
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

    if (ibv_query_gid(ibv_ctx, 1, 3, gid)) {
        printf("failed to query port gid\n");
        exit(__LINE__);
    }

    return 0;
}

void create_helper_qp(struct pingpong_context *ctx)
{
    ctx->helper_cq = ibv_create_cq(ctx->ctxt, 16, NULL, NULL, 0);

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
        .send_cq = ctx->helper_cq,
        .recv_cq = ctx->helper_cq,
        .cap = qp_cap,

        .qp_type = IBV_QPT_RC,
        .comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
        .pd = ctx->pd,
        .send_ops_flags = IBV_QP_EX_WITH_RDMA_WRITE | IBV_QP_EX_WITH_SEND | IBV_QP_EX_WITH_RDMA_READ | IBV_QP_EX_WITH_LOCAL_INV,
    };

    struct mlx5dv_qp_init_attr qp_dv_attr = {
        .comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS,
        .send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
    };

    struct ibv_qp *qp = mlx5dv_create_qp(ctx->ctxt, &qp_attr, &qp_dv_attr);
    if (!qp) {
        fprintf(stderr, "failed to create helper qp\n");
    }

    enum ibv_qp_attr_mask mask = IBV_QP_STATE | IBV_QP_PORT | IBV_QP_PKEY_INDEX | IBV_QP_ACCESS_FLAGS;
    struct ibv_qp_attr attr = {
        .qp_state = IBV_QPS_INIT,
        .pkey_index = 0,
        .port_num = 1,
        .qp_access_flags = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ,
    };
    if (ibv_modify_qp(qp, &attr, mask)) {
        fprintf(stderr, "failed to modifyqp:0x%x to init\n", qp->qp_num);
        exit(__LINE__);
    }

    union ibv_gid gid = {};
    uint16_t lid = 0;
    query_gid_lid(qp->context, &gid, &lid);

    mask = IBV_QP_STATE | IBV_QP_AV | \
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
                .sgid_index = 3,
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

    ctx->helper_qp = qp;
}

struct ibv_qp* ctx_verb_qp_create(struct pingpong_context *ctx)
{
    struct ibv_qp *qp = NULL;

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
        .send_cq = ctx->send_cq,
        .recv_cq = ctx->recv_cq,
        .cap = qp_cap,

        .qp_type = IBV_QPT_RAW_PACKET,
        .comp_mask = IBV_QP_INIT_ATTR_PD | IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
        .pd = ctx->pd,
        .send_ops_flags = IBV_QP_EX_WITH_SEND, // | IBV_QP_EX_WITH_LOCAL_INV,
    };

    struct mlx5dv_qp_init_attr qp_dv_attr = {
        // .comp_mask = MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS,
        // .send_ops_flags = MLX5DV_QP_EX_WITH_MKEY_CONFIGURE,
    };

    qp = mlx5dv_create_qp(ctx->ctxt, &qp_attr, &qp_dv_attr);

    if (qp == NULL) {
        fprintf(stderr, "failed to create RAW ethernet qp under verbs\n");
    }

    return qp;
}

static uint16_t ip_checksum(union IP_V4_header_raw *iph, size_t hdr_len)
{
    size_t idx = hdr_len / 4;
    unsigned long long sum = 0;

    while (idx)
        sum += iph->raw[--idx];
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return(~sum);
}

void create_raw_eth_pkt(struct pingpong_context *ctx,
    struct raw_ethernet_info *my_dest_info,
    struct raw_ethernet_info *rem_dest_info)
{
    struct tc_params *param = ctx->param;

    int pkt_size = param->buff_size;

    // generate eth header
    uint16_t eth_type = param->is_ethertype ? param->ethertype : 0x800; //IP_ETHER_TYPE;
    struct eth_header* eth_header = (void*)ctx->buf;
    memcpy(eth_header->src_mac, my_dest_info->mac, 6);
    memcpy(eth_header->dst_mac, rem_dest_info->mac, 6);
    eth_header->eth_type = htons(eth_type);

    // generate ipv4 header
    pkt_size = pkt_size - sizeof(struct eth_header); // no vlan 802.1Q tag optional space
    uint16_t ip_next_protocol = 0x11; // UDP_PROTOCOL
    void *ip_header_buf = (void*)eth_header + sizeof(struct eth_header);
    union IP_V4_header_raw raw;
    memset(&raw.ip_header, 0, sizeof(struct IP_V4_header));
    raw.ip_header.version = 4;
    raw.ip_header.ihl = 5;
    raw.ip_header.tos = 0;
    raw.ip_header.tot_len = htons(pkt_size);
    raw.ip_header.frag_off = htons(0);
    raw.ip_header.ttl = 255;
    raw.ip_header.protocol = ip_next_protocol;
    raw.ip_header.saddr = my_dest_info->ip;
    raw.ip_header.daddr = rem_dest_info->ip,
    raw.ip_header.check = ip_checksum(&raw, sizeof(struct IP_V4_header));
    memcpy(ip_header_buf, &raw.ip_header, sizeof(struct IP_V4_header));
    pkt_size = pkt_size - sizeof(struct IP_V4_header);

    // generate udp header
    void* udp_header_buf = ip_header_buf + sizeof(struct IP_V4_header);
    struct UDP_header udp_header;
    memset(&udp_header, 0, sizeof(struct UDP_header));
    udp_header.uh_sport = htons(my_dest_info->port);
    udp_header.uh_dport = htons(rem_dest_info->port);
    udp_header.uh_ulen = htons(pkt_size);
    udp_header.uh_sum = 0;
    memcpy(udp_header_buf, &udp_header, sizeof(struct UDP_header));
}

int main(int argc, char *argv[])
{
    struct tc_params param;
    parser(&param, argv, argc);

    struct pingpong_context ctx = {};
    ctx.ctxt = get_dev_ctx(param.ib_devname);
    ctx.param = &param;

    struct ibv_flow_attr *flow_rule = NULL;
    if (param.machine == 1) { // server
        set_up_flow_rule(&flow_rule, &param, param.server_port, param.client_port);
        print_spec(flow_rule, &param);
    }

    struct raw_ethernet_info *my_dest_info =
        calloc(1, sizeof(struct raw_ethernet_info));
    struct raw_ethernet_info *rem_dest_info =
        calloc(1, sizeof(struct raw_ethernet_info));
    if (param.machine == 0) { // client
        memcpy(my_dest_info->mac, param.source_mac, sizeof(param.source_mac));
        my_dest_info->ip = param.client_ip;
        my_dest_info->port = param.client_port;

        memcpy(rem_dest_info->mac, param.dest_mac, sizeof(param.dest_mac));
        rem_dest_info->ip = param.server_ip;
        rem_dest_info->port = param.server_port;
    }

    ctx.pd = ibv_alloc_pd(ctx.ctxt);

    ctx.buf = malloc(ctx.param->buff_size);

    int flags = IBV_ACCESS_LOCAL_WRITE;
    ctx.mr = ibv_reg_mr(ctx.pd, ctx.buf, ctx.param->buff_size, flags);
    memset(ctx.buf, 'a', ctx.param->buff_size);

    ctx.send_cq = ibv_create_cq(ctx.ctxt, 16, NULL, NULL, 0);
    if (!ctx.send_cq) {
        fprintf(stderr, "Couldn't create send_cq\n");
    }

    ctx.recv_cq = ibv_create_cq(ctx.ctxt, 16, NULL, NULL, 0);
    if (!ctx.recv_cq) {
        fprintf(stderr, "Couldn't create recv_cq\n");
    }

    ctx.qp = ctx_verb_qp_create(&ctx);

    ctx_modify_qp_to_init(&ctx);

    struct ibv_flow *flow_create_result = NULL;
    if (param.machine == 0) {
        create_raw_eth_pkt(&ctx, my_dest_info, rem_dest_info);
    } else {
        flow_create_result = ibv_create_flow(ctx.qp, flow_rule);
        if (flow_create_result == NULL) {
            fprintf(stderr, "Couldn't attach QP\n");
        }
    }

    struct ibv_qp_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.qp_state = IBV_QPS_RTR;
    attr.ah_attr.src_path_bits = 0;
    attr.ah_attr.port_num = 1;
    if (ibv_modify_qp(ctx.qp, &attr, IBV_QP_STATE)) {
        fprintf(stderr, "Failed to modify QP:0x%x to RTR\n", ctx.qp->qp_num);
        return -1;
    };

    if (param.machine == 0) {
        attr.qp_state = IBV_QPS_RTS;
        if (ibv_modify_qp(ctx.qp, &attr, IBV_QP_STATE)) {
           fprintf(stderr, "Failed to modify QP:0x%x to RTS\n", ctx.qp->qp_num);
           return -1;
        }
    }

    if (param.machine == 1) {
        create_helper_qp(&ctx);

        ctx.pi_mr = ibv_reg_mr(ctx.pd, malloc(4), 4, IBV_ACCESS_LOCAL_WRITE);
        memset(ctx.pi_mr->addr, 'a', 4);

        ctx.sig_mkey = create_sig_mkey(ctx.pd);

        if (reg_sig_mkey(&ctx, SIG_MODE_INSERT_ON_MEM)) {
            printf("failed to register sig mkey\n");
        }
    }

    if (param.machine == 0) {
        struct ibv_sge sge = {};
        sge.addr = (uintptr_t)ctx.buf;
        sge.length = ctx.param->buff_size;
        sge.lkey = ctx.mr->lkey;

        struct ibv_send_wr sr = {};
        sr.sg_list = &sge;
        sr.num_sge = 1;
        sr.wr_id = 0xcafebeef;
        sr.next = NULL;
        sr.send_flags = IBV_SEND_SIGNALED;
        sr.opcode = IBV_WR_SEND;

        struct ibv_send_wr *bad_sr = NULL;
        if (ibv_post_send(ctx.qp, &sr, &bad_sr)) {
            fprintf(stderr, "Failed to post send wr\n");
        }

        int ne = 0;
        struct ibv_wc wc = {};
        do {
            ne = ibv_poll_cq(ctx.send_cq, 1, &wc);
        } while(ne != 1);

        if (wc.status != IBV_WC_SUCCESS || wc.wr_id != 0xcafebeef) {
            printf("Client failed to send the data\n");
        } else {
            printf("Client has send the data\n");
        }
    } else {
        struct ibv_sge sge = {};
        sge.addr = 0;
        sge.length = 512;
        sge.lkey = ctx.sig_mkey->lkey;
        memset(ctx.buf, 0, sge.length);

        struct ibv_recv_wr rr = {};
        rr.sg_list = &sge;
        rr.num_sge = 1;
        rr.wr_id = 0xcafebeef;
        rr.next = NULL;

        struct ibv_recv_wr *bad_rr = NULL;
        if (ibv_post_recv(ctx.qp, &rr, &bad_rr)) {
            fprintf(stderr, "Failed to post recv wr\n");
            return -1;
        }

        int ne = 0;
        struct ibv_wc wc = {};
        do {
            ne = ibv_poll_cq(ctx.recv_cq, 1, &wc);
        } while(ne != 1);

        if (wc.status != IBV_WC_SUCCESS || wc.wr_id != 0xcafebeef) {
            printf("Server failed to recv data\n");
        } else {
            printf("Server has get the data\n");
        }

        if (check_sig_mkey(ctx.sig_mkey) < 0) {
            return -1;
        }

        info("offload CRC32C: 0x%x\n", *(uint32_t*)ctx.pi_mr->addr);
        info("sw calc CRC32C: 0x%x\n", crc32c(ctx.mr->addr, 512, 0));

        if (inv_sig_mkey(&ctx)) return -1;

        char *data = ctx.buf;
        printf("tail 8 bytes is:0x%02x%02x%02x%02x 0x%02x%02x%02x%02x\n", data[504], data[505], data[506], data[507], data[508], data[509], data[510], data[511]);
    }

    return 0;
}
