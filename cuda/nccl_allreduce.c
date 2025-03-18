/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>

#include <cuda_runtime.h>
#include <nccl.h>
#include <mpi.h>

/*Compile:
 * $ mpicc -o allreduce nccl_allreduce.c -I/usr/local/cuda/include -I$PWD/l40s/testroot/include -L/usr/local/cuda/lib64 -L$PWD/l40s/testroot/lib -lnccl -lcudart -lcuda -lmpi
 *
 *Run:
 * $ mpirun --tag-output -n 2 -N 1 --hostfile test.hosts -x NCCL_IB_HCA=mlx5_2:1 -x NCCL_IB_GID_INDEX=3 -x CUDA_VISIBLE_DEVICES=0 -x NCCL_P2P_DISABLE=1 -x NCCL_SHM_DISABLE=1 -x MELLANOX_VISIBLE_DEVICES=2 -x NCCL_IB_DISABLE=0 -x NCCL_PROTO=SIMPLE -x NCCL_NET_GDR_READ=1 -x NCCL_NET_GDR_LEVEL=4 -x NCCL_NET=IB -x NCCL_ALGO=ring -x MLX5_SHUT_UP_BF=1 -x LD_LIBRARY_PATH=$TESTROOT/lib:$OMPI_HOME/lib:/usr/local/cuda/lib64 allreduce
 */

#define MPICHECK(cmd) do {                          \
    int e = cmd;                                    \
    if( e != MPI_SUCCESS ) {                        \
        printf("Failed: MPI error %s:%d '%d'\n",    \
            __FILE__,__LINE__, e);                  \
        exit(EXIT_FAILURE);                         \
    }                                               \
} while(0)

#define CUDACHECK(cmd) do {                           \
    cudaError_t e = cmd;                              \
    if( e != cudaSuccess ) {                          \
        printf("Failed: Cuda error %s:%d '%s'\n",     \
            __FILE__,__LINE__,cudaGetErrorString(e)); \
        exit(EXIT_FAILURE);                           \
    }                                                 \
} while(0)

#define NCCLCHECK(cmd) do {                           \
    ncclResult_t r = cmd;                             \
    if (r!= ncclSuccess) {                            \
        printf("Failed, NCCL error %s:%d '%s'\n",     \
            __FILE__,__LINE__,ncclGetErrorString(r)); \
        exit(EXIT_FAILURE);                           \
    }                                                 \
} while(0)

static
uint64_t getHostHash(const char* string)
{
    // Based on DJB2a, result = result * 33 ^ char
    uint64_t result = 5381;
    for (int c = 0; string[c] != '\0'; c++){
        result = ((result << 5) + result) ^ string[c];
    }
    return result;
}

static
void getHostName(char* hostname, int maxlen)
{
    gethostname(hostname, maxlen);
    for (int i=0; i< maxlen; i++) {
        if (hostname[i] == '.') {
            hostname[i] = '\0';
            return;
        }
    }
}

int main(int argc, char* argv[])
{
    int size = 16; // 4MB

    int myRank, nRanks;

    // initialize MPI
    MPICHECK(MPI_Init(&argc, &argv));
    MPICHECK(MPI_Comm_size(MPI_COMM_WORLD, &nRanks));
    MPICHECK(MPI_Comm_rank(MPI_COMM_WORLD, &myRank));

    int cfg_gpu_idx = 0;

    // calculate cfg_gpu_idx based on hostname which is used to select the GPU device
    uint64_t hostHashs[nRanks];
    char hostname[1024];
    getHostName(hostname, 1024);
    hostHashs[myRank] = getHostHash(hostname);
    MPICHECK(MPI_Allgather(MPI_IN_PLACE, 0, MPI_DATATYPE_NULL, hostHashs, sizeof(uint64_t), MPI_BYTE, MPI_COMM_WORLD));
    for (int rank_idx = 0; rank_idx < nRanks; rank_idx++) {
       if (rank_idx == myRank) break;
       if (hostHashs[rank_idx] == hostHashs[myRank]) cfg_gpu_idx++;
    }

    ncclUniqueId id;
    // get NCCL unique ID at rank 0 and broadcast it to all others
    if (myRank == 0) ncclGetUniqueId(&id);
    MPICHECK(MPI_Bcast((void *)&id, sizeof(id), MPI_BYTE, 0, MPI_COMM_WORLD));

    // pick the GPU dev based on cfg_gpu_idx
    CUDACHECK(cudaSetDevice(cfg_gpu_idx));

    float *sendbuff, *recvbuff;
    // allocte buffers from GPU device
    CUDACHECK(cudaMalloc((void**)(&sendbuff), size * sizeof(float)));
    CUDACHECK(cudaMemset(sendbuff, 1, size * sizeof(float)));
    float *hostSendBuff;
    hostSendBuff = (float *)malloc(size * sizeof(float));
    for (int i = 0; i < size; i++) {
        hostSendBuff[i] = i % 2;
    }
    CUDACHECK(cudaMemcpy(sendbuff, hostSendBuff, size * sizeof(float), cudaMemcpyHostToDevice));

    CUDACHECK(cudaMalloc((void**)&recvbuff, size * sizeof(float)));
    CUDACHECK(cudaMemset(recvbuff, 0, size * sizeof(float)));

    cudaStream_t s;
    // create an asynchronous stream
    CUDACHECK(cudaStreamCreate(&s));

    printf("total Ranks=%d, myRank=%d\n", nRanks, myRank);

    ncclComm_t comm;
    // initialize NCCL
    NCCLCHECK(ncclCommInitRank(&comm, nRanks, id, myRank));

    NCCLCHECK(ncclGroupStart());
    // communicate with NCCL
    NCCLCHECK(ncclAllReduce((const void*)sendbuff, (void*)recvbuff, size, ncclFloat, ncclSum, comm, s));
    NCCLCHECK(ncclGroupEnd());

    // sync CUDA Stream to complete NCCL communication
    CUDACHECK(cudaStreamSynchronize(s));

    // finialize NCCL
    NCCLCHECK(ncclCommDestroy(comm));

    float* hostRecvBuff = (float*)malloc(size * sizeof(float));
    CUDACHECK(cudaMemcpy(hostRecvBuff, recvbuff, size * sizeof(float), cudaMemcpyDeviceToHost));

    printf("Send Data: \n");
    for(int i = 0; i < size; i++){
        printf("%f ", hostSendBuff[i]);
    }
    printf("\n");

    printf("Recv Data: \n");
    for(int i = 0; i < size; i++){
        printf("%f ", hostRecvBuff[i]);
    }
    printf("\n");

    free(hostSendBuff);
    free(hostRecvBuff);

    //free device buffers
    CUDACHECK(cudaFree(sendbuff));
    CUDACHECK(cudaFree(recvbuff));

    //finalize MPI
    MPICHECK(MPI_Finalize());

    printf("[MPI Rank %d] Success \n", myRank);
    return 0;
}
