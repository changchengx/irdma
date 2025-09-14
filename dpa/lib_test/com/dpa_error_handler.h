/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#ifndef _DPA_ERROR_HANDLER_
#define _DPA_ERROR_HANDLER_

#include "flexio_api_wrapper.h"

#ifdef __DPA
void flexio_process_recoverable_error_handler(uint64_t error_dtctx);
#else
extern flexio_func_t flexio_process_recoverable_error_handler;
#endif

#endif
