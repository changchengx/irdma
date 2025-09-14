/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#ifndef _RPC_SUB_
#define _RPC_SUB_

#include "flexio_api_wrapper.h"

#ifdef __DPA
uint64_t rpc_sub(uint64_t arg1, uint64_t arg2);
#else
extern flexio_func_t rpc_sub;
#endif

#endif
