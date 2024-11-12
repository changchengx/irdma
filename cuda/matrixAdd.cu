/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>
#include <cuda.h>

/* $ nvcc -gencode arch=compute_89,code=sm_89 -o matrixAdd matrixAdd.cu
 * $ ./matrixAdd
 *   Resulting Matrix C:
 *   0.000000 0.000000 0.000000 0.000000
 *   2.000000 2.000000 2.000000 2.000000
 *   4.000000 4.000000 4.000000 4.000000
 *   6.000000 6.000000 6.000000 6.000000
 */

#define N 4 // Define the size of the matrices

__global__
void MatAdd(float A[N][N], float B[N][N], float C[N][N])
{
    int i = blockIdx.x * blockDim.x + threadIdx.x;
    int j = blockIdx.y * blockDim.y + threadIdx.y;

    if (i < N && j < N) {
        C[i][j] = A[i][j] + B[i][j];
    }
}

int main() {
    size_t size = N * N * sizeof(float);
    
    // Allocate host memory
    float *h_A = (float *)malloc(size);
    float *h_B = (float *)malloc(size);
    float *h_C = (float *)malloc(size);

    // Initialize input matrices
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
           /* h_A {{0,  1,  2,  3},
            *      {1,  2,  3,  4},
            *      {2,  3,  4,  5},
            *      {3,  4,  5,  6}}
            */
            h_A[i * N + j] = i + j;

           /* h_B {{0, -1, -2, -3},
            *      {1,  0, -1, -2},
            *      {2,  1,  0, -1},
            *      {3,  2,  1,  0}
            */
            h_B[i * N + j] = i - j;
        }
    }

    // Allocate device memory
    float (*d_A)[N], (*d_B)[N], (*d_C)[N];
    cudaMalloc((void **)&d_A, size);
    cudaMalloc((void **)&d_B, size);
    cudaMalloc((void **)&d_C, size);

    // Copy matrices from host to device
    cudaMemcpy(d_A, h_A, size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_B, h_B, size, cudaMemcpyHostToDevice);

    // Kernel invocation
    dim3 threadsPerBlock(2, 2);
    dim3 numBlocks((N + threadsPerBlock.x - 1) / threadsPerBlock.x, (N + threadsPerBlock.y - 1) / threadsPerBlock.y);
    
    MatAdd<<<numBlocks, threadsPerBlock>>>(d_A, d_B, d_C);

    // Copy result from device to host
    cudaMemcpy(h_C, d_C, size, cudaMemcpyDeviceToHost);

    // Print the result
    printf("Resulting Matrix C:\n");
    for (int i = 0; i < N; i++) {
        for (int j = 0; j < N; j++) {
            printf("%08f ", h_C[i * N + j]);
        }
        printf("\n");
    }

    // Free device memory
    cudaFree(d_A);
    cudaFree(d_B);
    cudaFree(d_C);

    // Free host memory
    free(h_A);
    free(h_B);
    free(h_C);

    return 0;
}
