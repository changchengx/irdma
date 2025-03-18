- Basic info
```bash
$ env | grep -i PKG
PKG_CONFIG_PATH=:/opt/mellanox/collectx/lib/x86_64-linux-gnu/pkgconfig:/opt/mellanox/flexio/lib/pkgconfig:/opt/mellanox/dpdk/lib/x86_64-linux-gnu/pkgconfig

$ ls -l /usr/lib/x86_64-linux-gnu/pkgconfig/doca-common.pc
lrwxrwxrwx 1 root root 64 Jan 30 23:16 /usr/lib/x86_64-linux-gnu/pkgconfig/doca-common.pc -> /opt/mellanox/doca/lib/x86_64-linux-gnu/pkgconfig/doca-common.pc

$ pkg-config --variable libdir doca-common
/opt/mellanox/doca/lib/x86_64-linux-gnu

$ ls -l /opt/mellanox/doca/lib/x86_64-linux-gnu | grep common
-rw-r--r-- 1 root root 2798058 Jan 30 23:16 libdoca_common.a
lrwxrwxrwx 1 root root      19 Jan 30 23:16 libdoca_common.so -> libdoca_common.so.2
lrwxrwxrwx 1 root root      27 Jan 30 23:16 libdoca_common.so.2 -> libdoca_common.so.2.10.0087
-rw-r--r-- 1 root root  899624 Jan 30 23:16 libdoca_common.so.2.10.0087

$ ls -l /opt/mellanox/doca/lib/x86_64-linux-gnu | grep libdoca_dma
-rw-r--r-- 1 root root  185996 Jan 30 23:16 libdoca_dma.a
lrwxrwxrwx 1 root root      16 Jan 30 23:16 libdoca_dma.so -> libdoca_dma.so.2
lrwxrwxrwx 1 root root      24 Jan 30 23:16 libdoca_dma.so.2 -> libdoca_dma.so.2.10.0087
-rw-r--r-- 1 root root   71920 Jan 30 23:16 libdoca_dma.so.2.10.0087

$ ls -l /opt/mellanox/doca/lib/x86_64-linux-gnu | grep libdoca_argp
-rw-r--r-- 1 root root  235308 Jan 30 23:16 libdoca_argp.a
lrwxrwxrwx 1 root root      17 Jan 30 23:16 libdoca_argp.so -> libdoca_argp.so.2
lrwxrwxrwx 1 root root      25 Jan 30 23:16 libdoca_argp.so.2 -> libdoca_argp.so.2.10.0087
-rw-r--r-- 1 root root   84384 Jan 30 23:16 libdoca_argp.so.2.10.0087
```
