# SPDX-License-Identifier: Apache-2.0
# Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>

dpa_calc:
	./tools/build_dpa.sh '-Icom' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax,-DFLEXIO_DEV_VER_USED=0x180A0000 -W -D__DPA -g' nv-dpa-bf3 src_obj  /tmp/build dpa_add.dpa.o dev/dpa_add.c
	./tools/build_dpa.sh '-Icom' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax,-DFLEXIO_DEV_VER_USED=0x180A0000 -W -D__DPA -g' nv-dpa-bf3 src_obj  /tmp/build dpa_sub.dpa.o dev/dpa_sub.c
	./tools/build_dpa.sh '-Icom' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax,-DFLEXIO_DEV_VER_USED=0x180A0000 -W -D__DPA -g' nv-dpa-bf3 src_obj  /tmp/build dpa_error_handler.dpa.o dev/dpa_error_handler.c
	./tools/build_dpa.sh '' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax, -W -g' nv-dpa-bf3 host_obj /tmp/build ' ' dpa_offload dpa_dev_offload.o dpa_add.dpa.o dpa_sub.dpa.o dpa_error_handler.dpa.o
	./tools/build_dpa.sh '' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax, -W -D__DPA -g' nv-dpa-bf3 host_shared_lib ' ' dpa_offload dpa_dev_offload dpa_add.dpa.o dpa_sub.dpa.o dpa_error_handler.dpa.o

	gcc -fPIC -c host/offload_ctx.c -o offload_ctx.o -DDEV_APP_NAME=dpa_offload -DFLEXIO_ALLOW_EXPERIMENTAL_API -DFLEXIO_VER_USED=0x180A0000 -I /opt/mellanox/flexio/include/ -I com -I inc

	gcc -fPIC -c host/offload_dev.c -o offload_dev.o -DFLEXIO_ALLOW_EXPERIMENTAL_API -I /opt/mellanox/flexio/include/ -I com -I inc

	gcc -fPIC -shared -o liboffload.so dpa_dev_offload.o offload_ctx.o offload_dev.o -L/opt/mellanox/flexio/lib/ -Wl,-lflexio -Wl,-libverbs
	dpacc-extract dpa_dev_offload.so -o dpa_dev_offload.rv5.elf
	dpa-objdump -sSdxl --mcpu=nv-dpa-bf3 dpa_dev_offload.rv5.elf > dpa_dev_offload.rv5.dmp.S

	gcc unit_test.c -o dpa_calc -I inc -I /opt/mellanox/flexio/include -L/opt/mellanox/flexio/lib/ -L. -Wl,-loffload

clean:
	rm -rf *.so *.o *.rv5* dpa_calc
