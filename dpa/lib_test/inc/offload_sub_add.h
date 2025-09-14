#ifndef _OFFLOAD_SUB_ADD
#define _OFFLOAD_SUB_ADD

#include <stdint.h>

#include "offload_ctx.h"

extern int offload_add(struct offload_ctx* ctx, uint64_t arg1, uint64_t arg2, uint64_t *rst);

extern int offload_sub(struct offload_ctx* ctx, uint64_t arg1, uint64_t arg2, uint64_t *rst);

#endif
