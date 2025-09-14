# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

project(
  'offload_sub_add',
  'c',
  version: '1.0'
)

project_root = meson.project_source_root()

# Initialize array to collect all object files
all_objects = []

# Process subdirectories to accumulate object files
subdir('dev')
subdir('host')

# Compose the shared library from all objects
liboffload_sub_add = custom_target(
  'liboffload_sub_add',
  input: all_objects,
  output: 'liboffload_sub_add.so',
  command: [
    'gcc',
    '-fPIC',
    '-shared',
    '-o', '@OUTPUT@',
    '@INPUT@',  # This will expand to all input files
    '-L/opt/mellanox/flexio/lib/',
    '-Wl,-lflexio',
    '-Wl,-libverbs',
  ],
  build_by_default: true,
)

# Build the executable binary
dpa_calc_exe = custom_target(
  'dpa_calc',
  input: 'unit_test.c',
  output: 'dpa_calc',
  command: [
    'gcc',
    '@INPUT@',
    '-o', '@OUTPUT@',
    '-I' + project_root / 'inc',
    '-L' + meson.current_build_dir(),
    '-Wl,-loffload_sub_add',
  ],
  depends: liboffload_sub_add,  # Ensure the library is built first
  build_by_default: true,
)
