/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2024 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <stdio.h>
#include <cuda.h>

/*Build: take L40S for example
 * $ nvidia-smi -L
 * GPU 0: NVIDIA L40S (UUID: GPU-b5efa9ba-8fda-999e-42e9-409f10cb6f78)
 * GPU 1: NVIDIA L40S (UUID: GPU-1ee92b64-2d96-843e-557b-4331a8004649)
 * GPU 2: NVIDIA L40S (UUID: GPU-29f96d36-7a69-22c5-ce1d-fd4d76f698de)
 * GPU 3: NVIDIA L40S (UUID: GPU-bf1d4cd9-0d39-7e27-de3b-0ca9815a26da)
 *
 * $ nvidia-smi --format=csv --query-gpu=compute_cap -i GPU-b5efa9ba-8fda-999e-42e9-409f10cb6f78
 * compute_cap
 * 8.9
 *
 * $ nvcc -gencode arch=compute_89,code=sm_89 -o vectorAdd vectorAdd.cu
 *
 *Run:
 * $ ./vectorAdd
 * Result: 2.000000 4.000000 6.000000 8.000000
 */

__global__
void VecAdd(float* A, float* B, float* C, int N)
{
    int i = threadIdx.x;
    if (i < N) {
        C[i] = A[i] + B[i];
    }
}

int main() {
    int N = 4;
    size_t size = N * sizeof(float);

    // Allocate input vectors h_A and h_B in host memory
    float *h_A = (float *)malloc(size);
    float *h_B = (float *)malloc(size);
    float *h_C = (float *)malloc(size);

    // Initialize input vectors
    for (int i = 0; i < N; i++) {
        h_A[i] = i + 1; // A = {1, 2, 3, 4}
        h_B[i] = i + 1; // B = {1, 2, 3, 4}
    }

    // Allocate vectors in device memory
    float *d_A, *d_B, *d_C;
    cudaMalloc((void **)&d_A, size);
    cudaMalloc((void **)&d_B, size);
    cudaMalloc((void **)&d_C, size);

    // Copy vectors from host memory to device memory
    cudaMemcpy(d_A, h_A, size, cudaMemcpyHostToDevice);
    cudaMemcpy(d_B, h_B, size, cudaMemcpyHostToDevice);

    // Launch kernel
    VecAdd<<<1, N>>>(d_A, d_B, d_C, N);

    // Copy result from device memory to host memory
    cudaMemcpy(h_C, d_C, size, cudaMemcpyDeviceToHost);

    // Print the result
    printf("Result: ");
    for (int i = 0; i < N; i++) {
        printf("%f ", h_C[i]);
    }
    printf("\n");

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
