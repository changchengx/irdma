/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#ifndef _PRIV_OFFLOAD_CTX
#define _PRIV_OFFLOAD_CTX

#include "offload_ctx.h"
#include "flexio_api_wrapper.h"

struct offload_ctx {
	uint64_t udbg_token;
	struct ibv_context *ibv_ctx;
	struct flexio_process *flexio_process;
	struct flexio_msg_stream *stream;
};

/* The macro for converting a logarithm to a value */
#define L2V(l) (1UL << (l))

/* dev msg stream buffer built from chunks of 2^FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE each */
#define MSG_HOST_BUFF_BSIZE (4 * L2V(FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE))

extern int offload_recoverable_error_handler_set(struct offload_ctx* ctx);

#endif
