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

#include <errno.h>
#include <linux/vfio.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <doca_error.h>
#include <doca_log.h>

#include <common.h>
#include <devemu_pci_common.h>
#include <devemu_pci_host_common.h>

DOCA_LOG_REGISTER(DEVEMU_PCI_DEVICE_DB_HOST);

/*
 * Run DOCA Device Emulation DB Host sample
 *
 * @pci_address [in]: Emulated device PCI address
 * @vfio_group [in]: VFIO group ID
 * @region_idx [in]: The index of the DB region
 * @db_idx [in]: The index of the DB in the DB region
 * @db_value [in]: The value to write to the DB
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t devemu_pci_device_db_host(const char *pci_address,
				       int vfio_group,
				       int region_idx,
				       uint16_t db_idx,
				       uint32_t db_value)
{
	doca_error_t result;
	struct devemu_host_resources resources = {0};

	resources.container_fd = -1;
	resources.group_fd = -1;
	resources.device_fd = -1;

	const struct bar_db_region_config *db_region_cfg = &db_configs[region_idx];
	size_t db_stride_size = (1UL << db_region_cfg->log_db_stride_size);
	size_t db_offset = db_idx * db_stride_size;
	if (db_offset > (db_region_cfg->region.size - sizeof(uint32_t))) {
		DOCA_LOG_ERR("The given DB index falls outside the DB region");
		return DOCA_ERROR_INVALID_VALUE;
	}

	result = init_vfio_device(&resources, vfio_group, pci_address);
	if (result != DOCA_SUCCESS) {
		devemu_host_resources_cleanup(&resources);
		return result;
	}

	result = map_bar_region_memory(&resources, &db_region_cfg->region, &resources.db_region);
	if (result != DOCA_SUCCESS) {
		devemu_host_resources_cleanup(&resources);
		return result;
	}

	/* Ring the DoorBell */
	*((uint32_t *)&resources.db_region.mem[db_offset]) = db_value;

	DOCA_LOG_INFO("Wrote a DB value of %u (BigEndian) at offset %zu", db_value, db_offset);

	return DOCA_SUCCESS;
}
