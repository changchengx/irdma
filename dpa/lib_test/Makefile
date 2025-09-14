dpa_calc:
	./tools/build_dpa.sh '-Icom' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax,-DFLEXIO_DEV_VER_USED=0x180A0000 -W -D__DPA -g' nv-dpa-bf3 src_obj  /tmp/build dpa_add.dpa.o dev/dpa_add.c
	./tools/build_dpa.sh '-Icom' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax,-DFLEXIO_DEV_VER_USED=0x180A0000 -W -D__DPA -g' nv-dpa-bf3 src_obj  /tmp/build dpa_sub.dpa.o dev/dpa_sub.c
	./tools/build_dpa.sh '' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax, -W -g' nv-dpa-bf3 host_obj /tmp/build ' ' dpa_offload dpa_sub_add_offload.o dpa_add.dpa.o dpa_sub.dpa.o
	./tools/build_dpa.sh '' '' '-nostdlib,-DE_MODE_LE,-mabi=lp64,-mno-relax, -W -D__DPA -g' nv-dpa-bf3 host_shared_lib ' ' dpa_offload dpa_sub_add_offload dpa_add.dpa.o dpa_sub.dpa.o

	gcc -fPIC -c host/offload_ctx.c -o offload_ctx.o -DDEV_APP_NAME=dpa_offload -DFLEXIO_ALLOW_EXPERIMENTAL_API -DFLEXIO_VER_USED=0x180A0000 -I /opt/mellanox/flexio/include/ -I com -I inc

	gcc -fPIC -c host/offload_sub_add.c -o offload_sub_add.o -DFLEXIO_ALLOW_EXPERIMENTAL_API -I /opt/mellanox/flexio/include/ -I com -I inc

	gcc -fPIC -shared -o liboffload_sub_add.so dpa_sub_add_offload.o offload_ctx.o offload_sub_add.o -L/opt/mellanox/flexio/lib/ -Wl,-lflexio -Wl,-libverbs
	dpacc-extract dpa_sub_add_offload.so -o dpa_offload_sub_add.rv5

	gcc unit_test.c -o dpa_calc -I inc -I /opt/mellanox/flexio/include -L/opt/mellanox/flexio/lib/ -L. -Wl,-loffload_sub_add

clean:
	rm -rf *.so *.o *.rv5 dpa_calc
