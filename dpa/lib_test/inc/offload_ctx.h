/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#ifndef _OFFLOAD_CTX
#define _OFFLOAD_CTX

struct offload_ctx;

extern int query_offload_status(struct offload_ctx* ctx);

extern int offload_crashed_dump(struct offload_ctx* ctx, const char *outdir);

extern void destroy_ctx(struct offload_ctx* ctx);

extern struct offload_ctx* create_ctx(const char* mlx5_dev_name);

#endif
