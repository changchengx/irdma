# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

build_dpacc = find_program(project_root / 'tools' / 'build_dpa.sh', required: true)

dpa_device_sources = files('dpa_add.c', 'dpa_sub.c')

dpa_device_source_objs = []

fs = import('fs')

# DPA specific compiler flags
dpa_cflags = '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax,-DFLEXIO_DEV_VER_USED=0x180A0000 -W -D__DPA -g'

# DPA only needs com directory includes (not inc)
dpa_include_flags = '-I' + project_root + '/com'

foreach dpa_device_source : dpa_device_sources
	dpa_device_source_objs += custom_target(
	fs.name(dpa_device_source),
    input: dpa_device_source,
    output: fs.name(dpa_device_source) + '.dpa.o',
    command: [
      build_dpacc,
      dpa_include_flags,
      '',
      dpa_cflags,
      'nv-dpa-bf3',
      'src_obj',
      '/tmp/build',
      '@OUTPUT@',
      '@INPUT@',
    ],
    build_by_default: true,
  )
endforeach

dpa_offload_sub_add_dev_obj = custom_target(
  'dpa_sub_add_offload',
  input: dpa_device_source_objs,
  output: 'dpa_sub_add_offload.o',
  command: [
    build_dpacc,
    '',
    '',
    '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax, -W -g',
    'nv-dpa-bf3',
    'host_obj',
    '/tmp/build',
    ' ',
    'dpa_offload',
    '@OUTPUT@',
    '@INPUT0@',
    '@INPUT1@',
  ],
  depends: dpa_device_source_objs,
  build_by_default: true,
)

# Add DPA object to the global collection
all_objects += [dpa_offload_sub_add_dev_obj]
