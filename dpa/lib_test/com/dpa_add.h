#ifndef _RPC_ADD_
#define _RPC_ADD_

#include "flexio_api_wrapper.h"

#ifdef __DPA
uint64_t rpc_add(uint64_t arg1, uint64_t arg2);
#else
extern flexio_func_t rpc_add;
#endif

#endif
