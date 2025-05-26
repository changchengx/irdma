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

#include "devemu_pci_host_common.h"

#include <linux/vfio.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#include <doca_log.h>
#include <doca_dev.h>

#define VFIO_GROUP_MAX_PATH 128
#define VFIO_CONTAINER_PATH "/dev/vfio/vfio"
#define VFIO_GROUP_PATH_FORMAT "/dev/vfio/%d"

DOCA_LOG_REGISTER(DEVEMU_PCI_HOST_COMMON);

/*
 * Validates the available VFIO group and container support
 *
 * @group_fd [in]: The VFIO group fd
 * @container_fd [in]: The VFIO container fd
 * @return: true if valid, false otherwise
 */
static bool validate_vfio_group_and_container(int group_fd, int container_fd)
{
	int vfio_api_version = ioctl(container_fd, VFIO_GET_API_VERSION);
	if (vfio_api_version != VFIO_API_VERSION) {
		DOCA_LOG_ERR("VFIO API version mismatch. compiled with %d, but runtime is %d",
			     VFIO_API_VERSION,
			     vfio_api_version);
		return false;
	}

	if (ioctl(container_fd, VFIO_CHECK_EXTENSION, VFIO_TYPE1v2_IOMMU) == 0) {
		DOCA_LOG_ERR("VFIO Type 1 IOMMU extension not supported");
		return false;
	}

	struct vfio_group_status group_status = {.argsz = sizeof(group_status)};

	int status = ioctl(group_fd, VFIO_GROUP_GET_STATUS, &group_status);
	if (status != 0) {
		DOCA_LOG_ERR("Failed to get status of VFIO group. Status=%d, errno=%d", status, errno);
		return false;
	}

	if ((group_status.flags & VFIO_GROUP_FLAGS_VIABLE) == 0) {
		DOCA_LOG_ERR("VFIO group not viable. Not all devices in IOMMU group are bound to vfio driver");
		return false;
	}

	return true;
}

/*
 * Add the VFIO group to the container
 *
 * @group_fd [in]: The VFIO group fd
 * @container_fd [in]: The VFIO container fd
 * @return: true on success, false otherwise
 */
static bool add_vfio_group_to_container(int group_fd, int container_fd)
{
	int status = ioctl(group_fd, VFIO_GROUP_SET_CONTAINER, &container_fd);
	if (status != 0) {
		DOCA_LOG_ERR("Failed to set group for container. Status=%d, errno=%d", status, errno);
		return false;
	}

	status = ioctl(container_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU);
	if (status != 0) {
		DOCA_LOG_ERR("Failed to set IOMMU type 1 extension for container. Status=%d, errno=%d", status, errno);
		return false;
	}

	return true;
}

/*
 * Enable the command bit in the PCI configuration space
 *
 * @resources [in]: The sample resources
 * @return: true on success, false otherwise
 */
static bool enable_pci_cmd(struct devemu_host_resources *resources)
{
	struct vfio_region_info reg = {.argsz = sizeof(reg)};

	reg.index = VFIO_PCI_CONFIG_REGION_INDEX;

	int status = ioctl(resources->device_fd, VFIO_DEVICE_GET_REGION_INFO, &reg);
	if (status != 0) {
		DOCA_LOG_ERR("Failed to get Config Region info. Status=%d, errno=%d", status, errno);
		return false;
	}

	uint16_t cmd = 0x6;
	if (pwrite(resources->device_fd, &cmd, 2, reg.offset + 0x4) != 2) {
		DOCA_LOG_ERR("Failed to enable PCI cmd. Failed to write to Config Region Space. Status=%d, errno=%d",
			     status,
			     errno);
		return false;
	}

	return true;
}

doca_error_t init_vfio_device(struct devemu_host_resources *resources, int vfio_group, const char *pci_address)
{
	char vfio_group_path[VFIO_GROUP_MAX_PATH];

	resources->container_fd = open(VFIO_CONTAINER_PATH, O_RDWR);
	if (resources->container_fd == -1) {
		DOCA_LOG_ERR("Failed to open VFIO container. errno=%d", errno);
		return DOCA_ERROR_DRIVER;
	}

	snprintf(vfio_group_path, sizeof(vfio_group_path), VFIO_GROUP_PATH_FORMAT, vfio_group);

	resources->group_fd = open(vfio_group_path, O_RDWR);
	if (resources->group_fd == -1) {
		DOCA_LOG_ERR("Failed to open VFIO group. errno=%d", errno);
		return DOCA_ERROR_DRIVER;
	}

	if (!validate_vfio_group_and_container(resources->group_fd, resources->container_fd))
		return DOCA_ERROR_NOT_SUPPORTED;

	if (!add_vfio_group_to_container(resources->group_fd, resources->container_fd))
		return DOCA_ERROR_DRIVER;

	resources->device_fd = ioctl(resources->group_fd, VFIO_GROUP_GET_DEVICE_FD, pci_address);
	if (resources->device_fd < 0) {
		DOCA_LOG_ERR("Failed to get device fd. errno=%d", errno);
		return DOCA_ERROR_DRIVER;
	}

	if (!enable_pci_cmd(resources))
		return DOCA_ERROR_DRIVER;

	return DOCA_SUCCESS;
}

doca_error_t map_bar_region_memory(struct devemu_host_resources *resources,
				   const struct bar_region_config *bar_region_config,
				   struct bar_mapped_region *mapped_mem)
{
	struct vfio_region_info reg = {.argsz = sizeof(reg)};

	reg.index = bar_region_config->bar_id;

	int status = ioctl(resources->device_fd, VFIO_DEVICE_GET_REGION_INFO, &reg);
	if (status != 0) {
		DOCA_LOG_ERR("Failed to get Bar Region info. Status=%d, errno=%d", status, errno);
		return DOCA_ERROR_DRIVER;
	}

	if (bar_region_config->start_address > reg.size ||
	    bar_region_config->size > (reg.size - bar_region_config->start_address)) {
		DOCA_LOG_ERR(
			"The provided stateful region exceeds the boundaries of the emulated device's bar. At bar %d, the size is %lluB, but requested to map region with start address %zu, and size of %zuB",
			bar_region_config->bar_id,
			reg.size,
			bar_region_config->start_address,
			bar_region_config->size);
		return DOCA_ERROR_INVALID_VALUE;
	}

	uint8_t *mem = mmap(0,
			    bar_region_config->size,
			    PROT_READ | PROT_WRITE,
			    MAP_SHARED,
			    resources->device_fd,
			    reg.offset + bar_region_config->start_address);
	if (mem == MAP_FAILED) {
		DOCA_LOG_ERR("Failed to memory map bar region: bar %d start address %zu size %zuB",
			     bar_region_config->bar_id,
			     bar_region_config->start_address,
			     bar_region_config->size);
		return DOCA_ERROR_DRIVER;
	}

	mapped_mem->size = bar_region_config->size;
	mapped_mem->mem = mem;

	return DOCA_SUCCESS;
}

void devemu_host_resources_cleanup(struct devemu_host_resources *resources)
{
	if (resources->dma_mem.mem != NULL)
		munmap(resources->dma_mem.mem, resources->dma_mem.size);
	if (resources->device_fd != -1)
		close(resources->device_fd);
	if (resources->group_fd != -1)
		close(resources->group_fd);
	if (resources->container_fd != -1)
		close(resources->container_fd);

	if (resources->stateful_region.mem != NULL)
		munmap(resources->stateful_region.mem, resources->stateful_region.size);
	if (resources->db_region.mem != NULL)
		munmap(resources->db_region.mem, resources->db_region.size);
	if (resources->msix_vector_to_fd != NULL)
		free(resources->msix_vector_to_fd);
}

doca_error_t parse_emulated_pci_address(const char *addr, char *parsed_addr)
{
	int addr_len = strnlen(addr, DOCA_DEVINFO_PCI_ADDR_SIZE) + 1;

	/* Check using > to make static code analysis satisfied */
	if (addr_len > DOCA_DEVINFO_PCI_ADDR_SIZE) {
		DOCA_LOG_ERR("Entered device PCI address exceeding the maximum size of %d",
			     DOCA_DEVINFO_PCI_ADDR_SIZE - 1);
		return DOCA_ERROR_INVALID_VALUE;
	}

	if (addr_len != DOCA_DEVINFO_PCI_ADDR_SIZE) {
		DOCA_LOG_ERR("Entered device PCI address does not match supported format: XXXX:XX:XX.X");
		return DOCA_ERROR_INVALID_VALUE;
	}

	strncpy(parsed_addr, addr, addr_len - 1);
	parsed_addr[addr_len - 1] = 0;

	return DOCA_SUCCESS;
}

doca_error_t register_emulated_pci_address_param(doca_argp_param_cb_t pci_callback)
{
	struct doca_argp_param *param;
	doca_error_t result;

	result = doca_argp_param_create(&param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(param, "p");
	doca_argp_param_set_long_name(param, "pci-addr");
	doca_argp_param_set_description(param, "PCI address of the emulated device. Format: XXXX:XX:XX.X");
	doca_argp_param_set_callback(param, pci_callback);
	doca_argp_param_set_type(param, DOCA_ARGP_TYPE_STRING);
	doca_argp_param_set_mandatory(param);
	result = doca_argp_register_param(param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t register_vfio_group_param(doca_argp_param_cb_t vfio_group_callback)
{
	struct doca_argp_param *vfio_group_param;
	doca_error_t result;

	result = doca_argp_param_create(&vfio_group_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(vfio_group_param, "g");
	doca_argp_param_set_long_name(vfio_group_param, "vfio-group");
	doca_argp_param_set_description(vfio_group_param, "VFIO group ID of the device. Integer");
	doca_argp_param_set_callback(vfio_group_param, vfio_group_callback);
	doca_argp_param_set_type(vfio_group_param, DOCA_ARGP_TYPE_INT);
	doca_argp_param_set_mandatory(vfio_group_param);
	result = doca_argp_register_param(vfio_group_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

doca_error_t register_region_index_param(const char *description, doca_argp_param_cb_t region_callback)
{
	struct doca_argp_param *region_index_param;
	doca_error_t result;

	result = doca_argp_param_create(&region_index_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create ARGP param: %s", doca_error_get_descr(result));
		return result;
	}
	doca_argp_param_set_short_name(region_index_param, "r");
	doca_argp_param_set_long_name(region_index_param, "region-index");
	doca_argp_param_set_description(region_index_param, description);
	doca_argp_param_set_callback(region_index_param, region_callback);
	doca_argp_param_set_type(region_index_param, DOCA_ARGP_TYPE_INT);
	result = doca_argp_register_param(region_index_param);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to register program param: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}
