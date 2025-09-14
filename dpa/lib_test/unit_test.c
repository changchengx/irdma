#include <stdio.h>

#include <offload_ctx.h>
#include <offload_sub_add.h>

int main(int argc, char **argv)
{
	struct offload_ctx* ctx = create_ctx("mlx5_0");
	if (ctx == NULL) {
		printf("Failed to create ctx\n");
	}
	uint64_t rst = 0;

	offload_add(ctx, 1, 5, &rst);
	printf("1 + 5 = %ld\n", rst);

	offload_sub(ctx, 2, 5, &rst);
	printf("5 - 2 = %ld\n", rst);

	destroy_ctx(ctx);

	return 0;
}
