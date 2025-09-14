/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#ifndef _OFFLOAD_DEV_
#define _OFFLOAD_DEV_

#include <stdint.h>

#include "offload_ctx.h"

extern int offload_add(struct offload_ctx* ctx, uint64_t arg1, uint64_t arg2, uint64_t *rst);

extern int offload_sub(struct offload_ctx* ctx, uint64_t arg1, uint64_t arg2, uint64_t *rst);

#endif
