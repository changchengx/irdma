/*
 * Build command: g++ x722_mcx4.cpp -libverbs -lrdmacm -o x722_mcx4
 *
 * Run:
 *   ./x722_mcx4 mlx5_0
 * Output:
 *    parent start query
 *    query device: mlx5_0
 *    parent end query
 *
 *    child start query
 *    query device: mlx5_0
 *    child end query
 *
 *
 * Run:
 *    ./x722_mcx4 i40iw0
 * Output:
 *    parent start query
 *    query device: i40iw0
 *    parent end query
 *
 *    child start query
 *    query device: i40iw0
 *    libi40iw-i40iw_uquery_device: query device failed and returned status code: 13
 *    child end query
 */
#include <sys/types.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include <string>
#include <iostream>

using namespace std;

int query_i40iw_mlx5_device(ibv_context* *device_context_list, const char * const dev_name)
{
  int result = 0;
  ibv_device_attr *device_attr(new ibv_device_attr);

  while(*device_context_list) {
    ibv_context* ibv_ctx = *device_context_list;
    const ibv_device* ibv_device = ibv_ctx->device;
    if (0 == strncmp(ibv_device->name, dev_name, strlen("i40iw0")) ||
        0 == strncmp(ibv_device->name, dev_name, strlen("mlx5_0"))) {
      cout << " query device: " << ibv_device->name << endl;
      result = ibv_query_device(ibv_ctx, device_attr);
      break;
    }
    device_context_list++;
  }

  return result;
}

int main(int argc, char* *args)
{
  const char* device_name = args[1];
parent:
  int device_count = 0;
  ibv_context* *device_context_list(rdma_get_devices(NULL));

  cout << " parent start query" << endl;
  query_i40iw_mlx5_device(device_context_list, device_name);
  cout << " parent end query" << endl << endl;

  pid_t fork_pid = fork();
  if (fork_pid != 0) {
    int status = 0;
    int err = waitpid(fork_pid, &status, 0);
    return err;
  } else {
child:
    int device_count = 0;
    ibv_context* *device_context_list(rdma_get_devices(NULL));

    cout << " child start query" << endl;
    query_i40iw_mlx5_device(device_context_list, device_name);
    cout << " child end query" << endl << endl;
  }
  return 0;
}
