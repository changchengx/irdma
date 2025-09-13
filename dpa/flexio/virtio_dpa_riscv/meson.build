# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

virtio_dpa_srcs = [
  'virtio_dpa.c'
]

virtio_dpa_name = 'virtio_dpa'
virtio_dpa_full_name = 'lib' + virtio_dpa_name + '.a'

virtio_dpa_include_dir = meson.current_source_dir()
virtio_dpa_includes = [join_paths(virtio_dpa_include_dir, 'virtio_dpa.h')]

# Device side DPA library build by meson command custom_target
# through doca_build_dpacc.sh script
virtio_dpa_target = custom_target('archive_' + virtio_dpa_name,
                  command: [build_dpacc, '--library',
                        '--archive_name', '@OUTPUT@',
                        '--external_cc_options', ','.join(dpacc_devicecc_array),
                        '--additional_dpacc_options', dpacc_options,
                        '--srcs', '@INPUT@'],
                  output: virtio_dpa_full_name,
                  input: virtio_dpa_srcs,
                  depend_files: virtio_dpa_includes,
                  build_by_default: true)

# Create dependency from DPA application for link with host side library
virtio_dpu_lib_dep_dpa = declare_dependency(link_args : join_paths(meson.current_build_dir(), virtio_dpa_full_name))
