/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright(c) 2025 Liu, Changcheng <changcheng.liu@aliyun.com>
 */

#include <string.h>

#include <benchmark/benchmark.h>

const uint32_t crc32c_table[256] = {
    0xad7d5351, 0x5f16d052, 0x4c4623a6, 0xbe2da0a5, 0x6ae7c44e, 0x988c474d, 0x8bdcb4b9, 0x79b737ba,
    0x27a40b9e, 0xd5cf889d, 0xc69f7b69, 0x34f4f86a, 0xe03e9c81, 0x12551f82, 0x0105ec76, 0xf36e6f75,
    0xbd23943e, 0x4f48173d, 0x5c18e4c9, 0xae7367ca, 0x7ab90321, 0x88d28022, 0x9b8273d6, 0x69e9f0d5,
    0x37faccf1, 0xc5914ff2, 0xd6c1bc06, 0x24aa3f05, 0xf0605bee, 0x020bd8ed, 0x115b2b19, 0xe330a81a,
    0x8dc0dd8f, 0x7fab5e8c, 0x6cfbad78, 0x9e902e7b, 0x4a5a4a90, 0xb831c993, 0xab613a67, 0x590ab964,
    0x07198540, 0xf5720643, 0xe622f5b7, 0x144976b4, 0xc083125f, 0x32e8915c, 0x21b862a8, 0xd3d3e1ab,
    0x9d9e1ae0, 0x6ff599e3, 0x7ca56a17, 0x8ecee914, 0x5a048dff, 0xa86f0efc, 0xbb3ffd08, 0x49547e0b,
    0x1747422f, 0xe52cc12c, 0xf67c32d8, 0x0417b1db, 0xd0ddd530, 0x22b65633, 0x31e6a5c7, 0xc38d26c4,
    0xec064eed, 0x1e6dcdee, 0x0d3d3e1a, 0xff56bd19, 0x2b9cd9f2, 0xd9f75af1, 0xcaa7a905, 0x38cc2a06,
    0x66df1622, 0x94b49521, 0x87e466d5, 0x758fe5d6, 0xa145813d, 0x532e023e, 0x407ef1ca, 0xb21572c9,
    0xfc588982, 0x0e330a81, 0x1d63f975, 0xef087a76, 0x3bc21e9d, 0xc9a99d9e, 0xdaf96e6a, 0x2892ed69,
    0x7681d14d, 0x84ea524e, 0x97baa1ba, 0x65d122b9, 0xb11b4652, 0x4370c551, 0x502036a5, 0xa24bb5a6,
    0xccbbc033, 0x3ed04330, 0x2d80b0c4, 0xdfeb33c7, 0x0b21572c, 0xf94ad42f, 0xea1a27db, 0x1871a4d8,
    0x466298fc, 0xb4091bff, 0xa759e80b, 0x55326b08, 0x81f80fe3, 0x73938ce0, 0x60c37f14, 0x92a8fc17,
    0xdce5075c, 0x2e8e845f, 0x3dde77ab, 0xcfb5f4a8, 0x1b7f9043, 0xe9141340, 0xfa44e0b4, 0x082f63b7,
    0x563c5f93, 0xa457dc90, 0xb7072f64, 0x456cac67, 0x91a6c88c, 0x63cd4b8f, 0x709db87b, 0x82f63b78,
    0x2f8b6829, 0xdde0eb2a, 0xceb018de, 0x3cdb9bdd, 0xe811ff36, 0x1a7a7c35, 0x092a8fc1, 0xfb410cc2,
    0xa55230e6, 0x5739b3e5, 0x44694011, 0xb602c312, 0x62c8a7f9, 0x90a324fa, 0x83f3d70e, 0x7198540d,
    0x3fd5af46, 0xcdbe2c45, 0xdeeedfb1, 0x2c855cb2, 0xf84f3859, 0x0a24bb5a, 0x197448ae, 0xeb1fcbad,
    0xb50cf789, 0x4767748a, 0x5437877e, 0xa65c047d, 0x72966096, 0x80fde395, 0x93ad1061, 0x61c69362,
    0x0f36e6f7, 0xfd5d65f4, 0xee0d9600, 0x1c661503, 0xc8ac71e8, 0x3ac7f2eb, 0x2997011f, 0xdbfc821c,
    0x85efbe38, 0x77843d3b, 0x64d4cecf, 0x96bf4dcc, 0x42752927, 0xb01eaa24, 0xa34e59d0, 0x5125dad3,
    0x1f682198, 0xed03a29b, 0xfe53516f, 0x0c38d26c, 0xd8f2b687, 0x2a993584, 0x39c9c670, 0xcba24573,
    0x95b17957, 0x67dafa54, 0x748a09a0, 0x86e18aa3, 0x522bee48, 0xa0406d4b, 0xb3109ebf, 0x417b1dbc,
    0x6ef07595, 0x9c9bf696, 0x8fcb0562, 0x7da08661, 0xa96ae28a, 0x5b016189, 0x4851927d, 0xba3a117e,
    0xe4292d5a, 0x1642ae59, 0x05125dad, 0xf779deae, 0x23b3ba45, 0xd1d83946, 0xc288cab2, 0x30e349b1,
    0x7eaeb2fa, 0x8cc531f9, 0x9f95c20d, 0x6dfe410e, 0xb93425e5, 0x4b5fa6e6, 0x580f5512, 0xaa64d611,
    0xf477ea35, 0x061c6936, 0x154c9ac2, 0xe72719c1, 0x33ed7d2a, 0xc186fe29, 0xd2d60ddd, 0x20bd8ede,
    0x4e4dfb4b, 0xbc267848, 0xaf768bbc, 0x5d1d08bf, 0x89d76c54, 0x7bbcef57, 0x68ec1ca3, 0x9a879fa0,
    0xc494a384, 0x36ff2087, 0x25afd373, 0xd7c45070, 0x030e349b, 0xf165b798, 0xe235446c, 0x105ec76f,
    0x5e133c24, 0xac78bf27, 0xbf284cd3, 0x4d43cfd0, 0x9989ab3b, 0x6be22838, 0x78b2dbcc, 0x8ad958cf,
    0xd4ca64eb, 0x26a1e7e8, 0x35f1141c, 0xc79a971f, 0x1350f3f4, 0xe13b70f7, 0xf26b8303, 0x00000000
};

uint32_t crc32c(uint32_t crc, const void *_data, size_t length)
{
    const uint8_t *data = (const uint8_t *) _data;
    while (length--) {
        crc = crc32c_table[~(*data++ ^ crc) & 0xFF] ^ (crc >> 8);
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
            case 16: crc = crc32c(0, gBuf, BUF_SIZE);
            case 15: crc = crc32c(0, gBuf, BUF_SIZE);
            case 14: crc = crc32c(0, gBuf, BUF_SIZE);
            case 13: crc = crc32c(0, gBuf, BUF_SIZE);
            case 12: crc = crc32c(0, gBuf, BUF_SIZE);
            case 11: crc = crc32c(0, gBuf, BUF_SIZE);
            case 10: crc = crc32c(0, gBuf, BUF_SIZE);
            case  9: crc = crc32c(0, gBuf, BUF_SIZE);
            case  8: crc = crc32c(0, gBuf, BUF_SIZE);
            case  7: crc = crc32c(0, gBuf, BUF_SIZE);
            case  6: crc = crc32c(0, gBuf, BUF_SIZE);
            case  5: crc = crc32c(0, gBuf, BUF_SIZE);
            case  4: crc = crc32c(0, gBuf, BUF_SIZE);
            case  3: crc = crc32c(0, gBuf, BUF_SIZE);
            case  2: crc = crc32c(0, gBuf, BUF_SIZE);
            case  1: crc = crc32c(0, gBuf, BUF_SIZE);
            }
	printf("crc = 0x%08x\n", crc);
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
