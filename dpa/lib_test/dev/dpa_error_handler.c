/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <dpa_error_handler.h>

__dpa_global__ void flexio_process_recoverable_error_handler(uint64_t error_dtctx)
{
	flexio_dev_print("==> DPA %s called error_ctx %#lx\n"
			"==> doing flexio_dev_thread_reschedule \n", __func__, error_dtctx);

	flexio_dev_thread_reschedule();
}
