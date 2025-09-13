# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

virtio_dpu_srcs = [
  'virtio_dpu.c'
]

virtio_dpu_inc = ['../include']
include_dirs = include_directories(virtio_dpu_inc)

virtio_datapath_lib = static_library('virtio_datapath',
    virtio_dpu_srcs,
    include_directories: include_dirs,
    dependencies: [flexio_dep, virtio_dpu_lib_dep_dpa],
    install: true)
