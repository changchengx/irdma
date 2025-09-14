/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>

#include "offload_ctx.h"
#include "priv_offload_ctx.h"

extern struct flexio_app *DEV_APP_NAME;

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)
const char *core_file_base_name = STRINGIFY(DEV_APP_NAME);

int query_offload_status(struct offload_ctx* ctx)
{
	return flexio_err_status_get(ctx->flexio_process);
}

int offload_crashed_dump(struct offload_ctx* ctx, const char *dir)
{
	flexio_status rst;
	char crash_file_path[200] = {};

	if (dir != NULL) {
		strcat(crash_file_path, dir);
		strcat(crash_file_path, "/");
		strncat(crash_file_path, core_file_base_name, sizeof(crash_file_path) - strlen(crash_file_path));
	} else {
		strcat(crash_file_path, "/tmp/");
		strncat(crash_file_path, core_file_base_name, sizeof(crash_file_path) - strlen(crash_file_path));
	}

	printf("coredump file is :%s\n", crash_file_path);

	rst = flexio_crash_data(ctx->flexio_process, crash_file_path);
	if (rst != FLEXIO_STATUS_SUCCESS) {
		fprintf(stderr, "flexio_crash_data failed: %d", rst);
		return rst;
	}

	rst = flexio_coredump_create(ctx->flexio_process, crash_file_path);
	if (rst != FLEXIO_STATUS_SUCCESS) {
		fprintf(stderr, "flexio_coredump_create failed: %d", rst);
		return rst;
	}

	return 0;
}

void destroy_ctx(struct offload_ctx* ctx)
{
	if (ctx->flexio_process && flexio_msg_stream_destroy(ctx->stream)) {
		printf("Failed to destroy device messaging environment\n");
	}

	if (flexio_process_destroy(ctx->flexio_process)) {
		printf("Failed to destroy process\n");
	}

	if (ctx->ibv_ctx && ibv_close_device(ctx->ibv_ctx)) {
		printf("Failed to destroy process\n");
	}

	free(ctx);
}

/* main function is used for initialize contexts, run RPC, and clean up contexts */
struct offload_ctx* create_ctx(const char* mlx5_dev_name)
{
	flexio_msg_stream_attr_t stream_fattr = {0};
	struct ibv_device **dev_list = NULL;
	struct offload_ctx *ctx = NULL;
	int i, err = 0;

	flexio_status status = flexio_version_set(FLEXIO_VER_USED);
	if (status == FLEXIO_STATUS_FAILED) {
		printf("version not compatible\n");
		return NULL;
	}

	ctx = calloc(1, sizeof(*ctx));
	if (ctx == NULL) {
		printf("Failed to allocate offload_ctx\n");
	}

	/* Query IBV devices list. */
	dev_list = ibv_get_device_list(NULL);
	if (!dev_list) {
		printf("Failed to get IB devices list (err = %d)\n", errno);
		err = -1;
		goto clean_up;
	}

	for (i = 0; dev_list[i]; i++) {
		if (!strcmp(ibv_get_device_name(dev_list[i]), mlx5_dev_name))
			break;
	}

	if (!dev_list[i]) {
		printf("No IB device named '%s' was not found\n", mlx5_dev_name);
		err = -1;
		goto clean_up;
	}

	printf("Registered on device %s\n", mlx5_dev_name);

	/* Open the IBV device context for the requested device. */
	ctx->ibv_ctx = ibv_open_device(dev_list[i]);
	if (!ctx->ibv_ctx) {
		printf("Couldn't get context for %s (err = %d)\n", mlx5_dev_name, errno);
		err = -1;
		goto clean_up;
	}
	ibv_free_device_list(dev_list);

	err = flexio_process_create(ctx->ibv_ctx, DEV_APP_NAME, NULL, &ctx->flexio_process);
	if (err) {
		printf("Failed to create Flex IO process\n");
		goto clean_up;
	}

	ctx->udbg_token = flexio_process_udbg_token_get(ctx->flexio_process);
	printf("Use token >>> %#lx <<< for debug\n", ctx->udbg_token);

	err = offload_recoverable_error_handler_set(ctx);
	if (err) {
		printf("Failed to set error handler when flexio process in abnormal status\n");
		goto clean_up;
	}

	stream_fattr.data_bsize = MSG_HOST_BUFF_BSIZE;
	stream_fattr.sync_mode = FLEXIO_LOG_DEV_SYNC_MODE_SYNC;
	stream_fattr.level = FLEXIO_MSG_DEV_INFO;
	err = flexio_msg_stream_create(ctx->flexio_process, &stream_fattr, stdout, NULL, &ctx->stream);
	if (err) {
		printf("Failed to init device messaging environment\n");
		goto clean_up;
	}

	return ctx;

clean_up:
	destroy_ctx(ctx);

	return NULL;
}
