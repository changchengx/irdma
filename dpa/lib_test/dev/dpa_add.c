/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <dpa_add.h>

__dpa_rpc__ uint64_t rpc_add(uint64_t arg1, uint64_t arg2)
{
	uint64_t res;

	res = arg1 + arg2;

	// *(volatile int*)(0) = 1; // dpa coredump debug purpose

	return res;
}
