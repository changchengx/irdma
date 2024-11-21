/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

/* Build:
 * $ gcc -o raw_qp raw_ethernet_send.c -libverbs
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
 *   $ sudo ./raw_qp --port=20258 --ib-dev=mlx5_0 --local_mac a0:88:c2:f5:dd:1a --remote_mac a0:88:c2:f5:ee:9e --local_ip 192.168.33.15 --remote_ip 192.168.33.17 --local_port 8976 --remote_port 6789 --server
 *
 *  Client
 *   $ sudo ./raw_qp --port=20258 --ib-dev=mlx5_6 --local_mac a0:88:c2:f5:ee:9e --remote_mac a0:88:c2:f5:dd:1a --local_ip 192.168.33.17 --remote_ip 192.168.33.15 --local_port 6789 --remote_port 8976 --client
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <endian.h>

#include <unistd.h>
#include <getopt.h>

#include <arpa/inet.h>

#include <infiniband/verbs.h>

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

struct ibv_qp* ctx_verb_qp_create(struct pingpong_context *ctx)
{
    struct ibv_qp *qp = NULL;

    struct ibv_qp_init_attr attr;
    memset(&attr, 0, sizeof(struct ibv_qp_init_attr));
    attr.srq = NULL;
    attr.qp_type = IBV_QPT_RAW_PACKET;

    attr.send_cq = ctx->send_cq;
    attr.recv_cq = ctx->recv_cq;

    attr.cap.max_inline_data = 0;
    attr.cap.max_send_wr = 2;
    attr.cap.max_send_sge = 1;

    attr.cap.max_recv_wr = 2;
    attr.cap.max_recv_sge = 1;

    qp = ibv_create_qp(ctx->pd, &attr);

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
    pkt_size = pkt_size - sizeof(struct eth_header) - 4; // no vlan 802.1Q tag optional space
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

    printf("local_mac: %02x:%02x:%02x:%02x:%02x:%02x \n"
           "source_mac: %02x:%02x:%02x:%02x:%02x:%02x \n"
           "remote_mac: %02x:%02x:%02x:%02x:%02x:%02x \n"
           "dest_mac: %02x:%02x:%02x:%02x:%02x:%02x \n"
           "local_ip: 0x%08x retmote_ip: 0x%08x, \n"
           "client_ip: 0x%08x server_ip: 0x%08x\n"
           "server_port: 0x%08x, client_port: 0x%08x \n"
           "local_port: 0x%08x, remote_port: 0x%08x \n"
           "is_source_mac: %d, is_dest_mac: %d, is_client_ip: %d, is_server_ip: %d \n"
           "is_server_port: %d, is_client_port: %d, is_ethertype: %d, ethertype: %d \n"
           "machine: %d\n",
           param.local_mac[0], param.local_mac[1], param.local_mac[2],
           param.local_mac[3], param.local_mac[4], param.local_mac[5],
           param.source_mac[0], param.source_mac[1], param.source_mac[2],
           param.source_mac[3], param.source_mac[4], param.source_mac[5],
           param.remote_mac[0], param.remote_mac[1], param.remote_mac[2],
           param.remote_mac[3], param.remote_mac[4], param.remote_mac[5],
           param.dest_mac[0], param.dest_mac[1], param.dest_mac[2],
           param.dest_mac[3], param.dest_mac[4], param.dest_mac[5],
           param.local_ip, param.remote_ip,
           param.client_ip, param.server_ip,
           param.server_port, param.client_port,
           param.local_port, param.remote_port,
           param.is_srce_mac, param.is_dest_mac,
           param.is_client_ip, param.is_server_ip,
           param.is_server_port, param.is_client_port,
           param.is_ethertype, param.ethertype, param.machine);

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

    struct ibv_cq_init_attr_ex send_cq_attr = {
        .cqe = 16,
        .cq_context = NULL,
        .channel = NULL,
        .comp_vector = 0,
    };

    ctx.send_cq = ibv_cq_ex_to_cq(ibv_create_cq_ex(ctx.ctxt, &send_cq_attr));
    if (!ctx.send_cq) {
        fprintf(stderr, "Couldn't create send_cq\n");
    }

    struct ibv_cq_init_attr_ex recv_cq_attr = {
        .cqe = 16,
        .cq_context = NULL,
        .channel = NULL,
        .comp_vector = 0,
    };

    ctx.recv_cq = ibv_cq_ex_to_cq(ibv_create_cq_ex(ctx.ctxt, &recv_cq_attr));
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

    if (param.machine == 0) {
        struct ibv_sge sge = {};
        sge.addr = (uintptr_t)ctx.buf;
        sge.length = ctx.param->buff_size - 4; // 4 bytes for FCS
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
        sge.addr = (uintptr_t)ctx.buf;
        sge.length = ctx.param->buff_size;
        sge.lkey = ctx.mr->lkey;
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

        char *data = ctx.buf;
        printf("tail 8 bytes is:0x%02x%02x%02x%02x 0x%02x%02x%02x%02x\n", data[504], data[505], data[506], data[507], data[508], data[509], data[510], data[511]);
    }

    return 0;
}
