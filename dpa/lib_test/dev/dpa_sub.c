/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <dpa_sub.h>

__dpa_rpc__ uint64_t rpc_sub(uint64_t arg1, uint64_t arg2)
{
	uint64_t res;

	if (arg1 > arg2) {
		res = arg1 - arg2;
	} else {
		res = arg2 - arg1;
	}

	return res;
}
