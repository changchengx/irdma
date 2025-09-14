#include <dpa_add.h>

__dpa_rpc__ uint64_t rpc_add(uint64_t arg1, uint64_t arg2)
{
	uint64_t res;

	res = arg1 + arg2;

	flexio_dev_print("Calculate: %lu + %lu = %lu\n", arg1, arg2, res);

	return res;
}
