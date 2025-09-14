#ifndef _OFFLOAD_CTX
#define _OFFLOAD_CTX

struct offload_ctx {
	struct ibv_context *ibv_ctx;
	struct flexio_process *flexio_process;
	struct flexio_msg_stream *stream;
};

/* The macro for converting a logarithm to a value */
#define L2V(l) (1UL << (l))

/* dev msg stream buffer built from chunks of 2^FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE each */
#define MSG_HOST_BUFF_BSIZE (4 * L2V(FLEXIO_MSG_DEV_LOG_DATA_CHUNK_BSIZE))

extern void destroy_ctx(struct offload_ctx* ctx);

extern struct offload_ctx* create_ctx(const char* mlx5_dev_name);

#endif
