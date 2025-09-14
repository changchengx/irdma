#include "offload_sub_add.h"

#include "dpa_add.h"
#include "dpa_sub.h"

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
