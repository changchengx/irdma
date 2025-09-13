/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

/* Used for sleep function */
#include <unistd.h>

/* Used for strtoimax function */
#include <inttypes.h>

/* Flex IO SDK host side version API header. */
#include <libflexio/flexio_ver.h>

/* Flex IO SDK host side API header. */
#include <libflexio/flexio.h>

extern flexio_func_t rpc_calculate;

int calculate(uint64_t arg1, uint64_t arg2)
{
	uint64_t func_ret;
	int err = 0;

	err = flexio_process_call(NULL, &rpc_calculate, &func_ret, arg1, arg2);

	return err == 0 ? func_ret : 0;
}
