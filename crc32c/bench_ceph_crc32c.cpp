/*
 * Step1:
 * # cd /root/crc32c
 * # sudo dnf install cmake3 git gcc gcc-c++
 * # [crc32c]# git clone https://github.com/google/benchmark
 * # [crc32c]# cd benchmark
 * # [benchmark]# mkdir build && cd build
 * # [build]# cmake -DBENCHMARK_DOWNLOAD_DEPENDENCIES=ON ../
 * # [build]# make
 * # [build]# make install
 *
 * Step2:
 * # cd irdma/crc32c
 * # mkdir -p build
 * # cmake ..
 * # cmake -DMAX_CRC32C_TASK_SIZE=16 -S .. -B .
 * # make
 *
 * Step3:
 * # ./ceph_crc32c
 */

#include <string.h>

#include <benchmark/benchmark.h>

/*CRC implement*/
#define CRC32CX(crc, value) __asm__("crc32cx %w[c], %w[c], %x[v]":[c]"+r"(crc):[v]"r"(value))
#define CRC32CW(crc, value) __asm__("crc32cw %w[c], %w[c], %w[v]":[c]"+r"(crc):[v]"r"(value))
#define CRC32CH(crc, value) __asm__("crc32ch %w[c], %w[c], %w[v]":[c]"+r"(crc):[v]"r"(value))
#define CRC32CB(crc, value) __asm__("crc32cb %w[c], %w[c], %w[v]":[c]"+r"(crc):[v]"r"(value))

uint32_t ceph_crc32c_aarch64(uint32_t crc, unsigned char const *buffer, unsigned len)
{
    int64_t length = len;

    if (!buffer) {
        while ((length -= sizeof(uint64_t)) >= 0)
            CRC32CX(crc, 0);

        /* The following is more efficient than the straight loop */
        if (length & sizeof(uint32_t))
            CRC32CW(crc, 0);

        if (length & sizeof(uint16_t))
            CRC32CH(crc, 0);

        if (length & sizeof(uint8_t))
            CRC32CB(crc, 0);
    } else {
        while ((length -= sizeof(uint64_t)) >= 0) {
            CRC32CX(crc, *(uint64_t *)buffer);
            buffer += sizeof(uint64_t);
        }

        /* The following is more efficient than the straight loop */
        if (length & sizeof(uint32_t)) {
            CRC32CW(crc, *(uint32_t *)buffer);
            buffer += sizeof(uint32_t);
        }

        if (length & sizeof(uint16_t)) {
            CRC32CH(crc, *(uint16_t *)buffer);
            buffer += sizeof(uint16_t);
        }

        if (length & sizeof(uint8_t))
            CRC32CB(crc, *buffer);
    }

    return crc;
}

#define BUF_SIZE    (4096)
#define BATCH        100000

static unsigned char gBuf[BUF_SIZE];

static void BM_Crc32cFixedBuf(benchmark::State& state)  // NOLINT(runtime/references)
{
    uint32_t crc = 0;
    while (state.KeepRunningBatch(BATCH)) {
        for (int i = 0; i < BATCH; ++i)
            switch(MAX_CRC_TASK_SIZE) {
            case 16: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case 15: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case 14: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case 13: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case 12: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case 11: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case 10: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  9: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  8: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  7: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  6: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  5: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  4: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  3: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  2: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            case  1: crc = ceph_crc32c_aarch64(0, gBuf, BUF_SIZE);
            }
    }

    state.SetItemsProcessed(state.iterations());
    printf("CRC32C = 0X%08X\n", crc);
}

BENCHMARK(BM_Crc32cFixedBuf);

int main(int argc, char** argv) {
    benchmark::Initialize(&argc, argv);

    memset(gBuf, 'a', BUF_SIZE);

    printf("\n========= CRC32C task size: 0x%x =========\n\n", MAX_CRC_TASK_SIZE);
    benchmark::RunSpecifiedBenchmarks();

    return 0;
}
