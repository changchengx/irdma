# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

project('virtio_datapath', 'c',
        version : '0.0.1',
        license : 'Apache-2.0')

# Dependencies for host side samples
ibverbs_dep = dependency('libibverbs', required: true)
mlx5_dep = dependency('libmlx5', required: true)
thread_dep = dependency('threads', required: true)
flexio_dep = dependency('libflexio', required: true)

# Use native C compiler for build host side
c = meson.get_compiler('c', native: true)
# Add warnings to host compile
add_project_arguments('-Wmissing-prototypes', language:'c', native: true)
add_project_arguments('-Wstrict-prototypes', language:'c', native: true)

# Get program for build device side library and applications
build_dpacc = find_program('/opt/mellanox/flexio/samples/doca_build_dpacc.sh', required: true)

# List of arguments that should be pass to build_dpacc
dpacc_devicecc_array = ['-DE_MODE_LE',
            '-Wall',
            '-Wextra',
            '-Wpedantic',
            '-Wdouble-promotion',
            '-Wno-empty-translation-unit',
            '-Wmissing-prototypes',
            '-Wstrict-prototypes',
            '-ffreestanding',
            '-mcmodel=medany',]
# Set warnings as error for device side libraries and applications
dpacc_devicecc_array += ['-Werror']

# Set HW model types for executables build
dpa_cpus = get_option('cpu')
dpa_cpus_str = '-mcpu=nv-dpa-' + ',nv-dpa-'.join(dpa_cpus)
dpacc_options = [dpa_cpus_str]

# Set optimization type for device side libraries and applications
# according of optimization type of host side
meson_build_type = get_option('buildtype')

if (meson_build_type == 'debug' or meson_build_type == '')
    dpacc_devicecc_array += ['-g', '-O0', '-gdwarf-4']
elif (meson_build_type == 'debugoptimized')
    dpacc_devicecc_array += ['-g', '-O2', '-gdwarf-4']
    dpacc_options += ['-flto']
elif (meson_build_type == 'release')
    dpacc_devicecc_array += ['-O3']
    dpacc_options += ['-flto']
else
    error('Unsupported build mode ', meson_build_type)
endif

subdir('include')
subdir('virtio_dpa_riscv')
subdir('virtio_dpu_arm')

pkg_mod = import('pkgconfig')
pkg_mod.generate(libraries : 'virtio_datapath',
     version : '0.0.1',
     name : 'libvirtio_datapath',
     filebase : 'virtio_datapath',
     description : 'A Library to offload basic virtio operation to DPA')
