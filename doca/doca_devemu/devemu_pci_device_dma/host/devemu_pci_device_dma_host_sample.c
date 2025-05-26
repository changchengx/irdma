/*
 * Copyright (c) 2024 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <devemu_pci_common.h>

#include <errno.h>
#include <fcntl.h>
#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <common.h>
#include <doca_error.h>
#include <doca_log.h>

#include <devemu_pci_host_common.h>

#define MEM_BUF_LEN (4 * 1024) /* Mem buffer size. It's the same as DPU side */

DOCA_LOG_REGISTER(DEVEMU_PCI_DEVICE_DMA_HOST);

/*
 * Allocate memory for DMA
 *
 * @resources [in]: The sample resources
 * @len [in]: The length of memory to allocate
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t allocate_dma_mem(struct devemu_host_resources *resources, int len)
{
	resources->dma_mem.size = len;
	resources->dma_mem.mem =
		mmap(0, resources->dma_mem.size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	if (resources->dma_mem.mem == MAP_FAILED) {
		DOCA_LOG_ERR("Failed to allocate(mmap) memory");
		return DOCA_ERROR_NO_MEMORY;
	}
	return DOCA_SUCCESS;
}

/*
 * IOMMU DMA map memory
 *
 * @resources [in]: The sample resources
 * @iova [in]: The IOVA DMA memory mapped to
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t map_dma_mem(struct devemu_host_resources *resources, uint64_t iova)
{
	struct vfio_iommu_type1_dma_map dma_map = {0};
	dma_map.argsz = sizeof(dma_map);
	dma_map.vaddr = (uint64_t)resources->dma_mem.mem;
	dma_map.size = resources->dma_mem.size;
	dma_map.iova = iova;
	dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
	int status = ioctl(resources->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map);
	if (status != 0) {
		DOCA_LOG_ERR("Failed to VFIO_IOMMU_MAP_DMA. Status=%d, errno=%d", status, errno);
		return DOCA_ERROR_DRIVER;
	}
	return DOCA_SUCCESS;
}

/*
 * IOMMU DMA unmap memory
 *
 * @resources [in]: The sample resources
 * @iova [in]: The IOVA DMA memory mapped to
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t unmap_dma_mem(struct devemu_host_resources *resources, uint64_t iova)
{
	/* DMA unmap */
	struct vfio_iommu_type1_dma_unmap dma_unmap = {0};
	dma_unmap.argsz = sizeof(dma_unmap);
	dma_unmap.iova = iova;
	dma_unmap.size = resources->dma_mem.size;
	int status = ioctl(resources->container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap);
	if (status != 0) {
		DOCA_LOG_ERR("Failed to VFIO_IOMMU_UNMAP_DMA. Status=%d, errno=%d", status, errno);
		return DOCA_ERROR_DRIVER;
	}
	return DOCA_SUCCESS;
}

/*
 * Run DOCA Device Emulation DMA Host sample
 *
 * @pci_address [in]: Emulated device PCI address
 * @vfio_group [in]: VFIO group ID
 * @write_data [in]: The data to write
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t devemu_pci_device_dma_host(const char *pci_address, int vfio_group, const char *write_data)
{
	doca_error_t result;
	uint64_t iova = 0x1000000;
	struct devemu_host_resources resources = {0};

	resources.container_fd = -1;
	resources.group_fd = -1;
	resources.device_fd = -1;

	result = init_vfio_device(&resources, vfio_group, pci_address);
	if (result != DOCA_SUCCESS) {
		devemu_host_resources_cleanup(&resources);
		return result;
	}

	result = allocate_dma_mem(&resources, MEM_BUF_LEN);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to allocate DMA memory");
		devemu_host_resources_cleanup(&resources);
		return result;
	}

	result = map_dma_mem(&resources, iova);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to DMA map memory to container");
		devemu_host_resources_cleanup(&resources);
		return DOCA_ERROR_DRIVER;
	}
	DOCA_LOG_INFO("Allocated DMA memory(IOVA): %#lx", iova);

	/* Write the data */
	memcpy(resources.dma_mem.mem, write_data, MEM_BUF_LEN);
	DOCA_LOG_INFO("Write to DMA memory: %s", write_data);

	/* Read the data, till having different content from DPU */
	while (1) {
		sleep(2);
		DOCA_LOG_INFO("Wait for new DMA data from DPU--- ---");
		if (memcmp(resources.dma_mem.mem, write_data, MEM_BUF_LEN) == 0)
			continue;

		DOCA_LOG_INFO("Read new data from DPU: %s", (char *)(resources.dma_mem.mem));
		break;
	};

	/* DMA unmap the memory*/
	result = unmap_dma_mem(&resources, iova);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to DMA unmap memory to container");
		devemu_host_resources_cleanup(&resources);
		return DOCA_ERROR_DRIVER;
	}

	devemu_host_resources_cleanup(&resources);
	return DOCA_SUCCESS;
}
