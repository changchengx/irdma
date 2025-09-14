/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>

#include <offload_ctx.h>
#include <offload_dev.h>

int main(int argc, char **argv)
{
	struct offload_ctx* ctx = create_ctx("mlx5_0");
	if (ctx == NULL) {
		printf("Failed to create ctx\n");
		return -1;
	}
	uint64_t rst = 0;

	if (offload_add(ctx, 1, 5, &rst)) {
		goto err;
	} else {
		printf("1 + 5 = %ld\n", rst);
	}

	if (offload_sub(ctx, 2, 5, &rst)) {
		goto err;
	} else {
		printf("5 - 2 = %ld\n", rst);
	}

	goto out;

err:
	fprintf(stderr, "offload_status: %d\n", query_offload_status(ctx));
	offload_crashed_dump(ctx, "/tmp");
out:
	destroy_ctx(ctx);

	return 0;
}
