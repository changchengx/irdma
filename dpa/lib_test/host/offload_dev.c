/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include "offload_dev.h"
#include "priv_offload_ctx.h"

#include "dpa_add.h"
#include "dpa_sub.h"
#include "dpa_error_handler.h"

int offload_recoverable_error_handler_set(struct offload_ctx* ctx)
{
	flexio_status status = flexio_process_error_handler_set(ctx->flexio_process, flexio_process_recoverable_error_handler);

	if (status != FLEXIO_STATUS_SUCCESS) {
		fprintf(stderr, "Failed to set error handler\n");
		return -1;
	} else {
		printf("set the flexio recoverable error handler to be flexio_process_recoverable_error_handler \n");
	}

	return 0;
}

int offload_add(struct offload_ctx* ctx, uint64_t arg1, uint64_t arg2, uint64_t *rst)
{
	uint64_t func_ret;
	int err = flexio_process_call(ctx->flexio_process, &rpc_add, &func_ret, arg1, arg2);

	if (err != 0) {
		return err;
	}

	*rst = func_ret;

	return 0;
}

int offload_sub(struct offload_ctx* ctx, uint64_t arg1, uint64_t arg2, uint64_t *rst)
{
	uint64_t func_ret;
	int err = flexio_process_call(ctx->flexio_process, &rpc_sub, &func_ret, arg1, arg2);

	if (err != 0) {
		return err;
	}

	*rst = func_ret;

	return 0;
}
