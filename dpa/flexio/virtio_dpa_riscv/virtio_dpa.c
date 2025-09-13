/* SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

/* Flex IO SDK device side version API header. */
#include <libflexio-dev/flexio_dev_ver.h>

/* Flex IO SDK device side API header. */
#include <libflexio-dev/flexio_dev.h>

/* Prevent "missing prototype" warning */
uint64_t rpc_calculate(uint64_t arg1, uint64_t arg2);

/* Entry point function that the host side calls for execution.
 *  arg1 and arg2 are arguments passed from the host side using
 * the flexio_process_call function.
 */
__dpa_rpc__ uint64_t rpc_calculate(uint64_t arg1, uint64_t arg2)
{
	uint64_t res;

	res = arg1 + arg2;

	flexio_dev_print("Calculate: %lu + %lu = %lu\n", arg1, arg2, res);

	return res;
}
