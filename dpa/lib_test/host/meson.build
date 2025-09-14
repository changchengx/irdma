# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

flexio_include = '/opt/mellanox/flexio/include/'

# Common compiler flags
common_cflags = [
  '-DFLEXIO_ALLOW_EXPERIMENTAL_API',
  '-DFLEXIO_VER_USED=0x180A0000'
]

# Build include flags for manual inclusion in custom_target commands
common_include_flags = [
  '-I' + project_root + '/com',
  '-I' + project_root + '/inc',
  '-I' + flexio_include
]

# Host specific compiler flags
host_cflags = ['-fPIC', '-c'] + common_cflags

offload_ctx_obj = custom_target(
  'offload_ctx_o',
  input: 'offload_ctx.c',
  output: 'offload_ctx.o',
  command: [
    'gcc',
  ] + host_cflags + [
    '@INPUT@',
    '-o', '@OUTPUT@',
    '-DDEV_APP_NAME=dpa_offload',
  ] + common_include_flags,
  build_by_default: true,
)

offload_sub_add_obj = custom_target(
  'offload_sub_add_o',
  input: 'offload_sub_add.c',
  output: 'offload_sub_add.o',
  command: [
    'gcc',
  ] + host_cflags + [
    '@INPUT@',
    '-o', '@OUTPUT@',
  ] + common_include_flags,
  build_by_default: true,
)

# Add host objects to the global collection
all_objects += [offload_ctx_obj, offload_sub_add_obj]
