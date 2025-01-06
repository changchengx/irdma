# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

cmake_minimum_required(VERSION 3.14)
project(MyBenchmarkProject)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

find_package(benchmark REQUIRED)

set(MAX_CRC32C_TASK_SIZE "1" CACHE STRING "Set the maximum CRC32C task size")
# Convert the value to an integer for comparison
math(EXPR MAX_CRC32C_TASK_SIZE_INT "${MAX_CRC32C_TASK_SIZE}")
# Check if the value is greater than 16
if(MAX_CRC32C_TASK_SIZE_INT GREATER 16)
    # Issue a warning message
    message(WARNING "The value of MAX_CRC32C_TASK_SIZE exceeds 16. Setting it to 16 #TODO: check max_qp_rd_atom.")

    # Set the value to 16
    set(MAX_CRC32C_TASK_SIZE "16" CACHE STRING "Set the maximum CRC32C task size" FORCE)
endif()

add_compile_definitions(MAX_CRC_TASK_SIZE=${MAX_CRC32C_TASK_SIZE})

add_executable(bench_ceph_crc32c bench_ceph_crc32c.cpp)
target_compile_options(bench_ceph_crc32c PRIVATE -march=armv8.3-a)
target_link_libraries(bench_ceph_crc32c PRIVATE benchmark::benchmark)

add_executable(check_rdma_crc32c check_rdma_crc32c.c)
target_link_libraries(check_rdma_crc32c ibverbs mlx5)

add_executable(client_remote_rdma_read_crc32c remote_rdma_read_crc32c.cpp)
target_link_libraries(client_remote_rdma_read_crc32c PRIVATE ibverbs mlx5)

add_executable(bench_sw_crc32c bench_sw_crc32c.cpp)
target_link_libraries(bench_sw_crc32c PRIVATE benchmark::benchmark)

add_executable(bench_lo_rdma_read_crc32c bench_lo_rdma_read_crc32c.cpp)
target_link_libraries(bench_lo_rdma_read_crc32c PRIVATE benchmark::benchmark ibverbs mlx5)

add_executable(bench_lo_rdma_read bench_lo_rdma_read.cpp)
target_link_libraries(bench_lo_rdma_read PRIVATE benchmark::benchmark ibverbs mlx5)

add_executable(bench_lo_rdma_write_crc32c bench_lo_rdma_write_crc32c.cpp)
target_link_libraries(bench_lo_rdma_write_crc32c PRIVATE benchmark::benchmark ibverbs mlx5)

add_executable(bench_remote_rdma_read bench_remote_rdma_read.cpp)
target_link_libraries(bench_remote_rdma_read PRIVATE benchmark::benchmark ibverbs mlx5)

add_executable(bench_remote_rdma_read_crc32c bench_remote_rdma_read_crc32c.cpp)
target_link_libraries(bench_remote_rdma_read_crc32c PRIVATE benchmark::benchmark ibverbs mlx5)
