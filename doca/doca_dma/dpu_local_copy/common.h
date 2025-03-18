/*
 * Copyright (c) 2022-2023 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
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

#ifndef COMMON_H_
#define COMMON_H_

#include <doca_error.h>
#include <doca_dev.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Function to check if a given device is capable of executing some task */
typedef doca_error_t (*tasks_check)(struct doca_devinfo *);

/* DOCA core objects used by the samples / applications */
struct program_core_objects {
	struct doca_dev *dev;		    /* doca device */
	struct doca_mmap *src_mmap;	    /* doca mmap for source buffer */
	struct doca_mmap *dst_mmap;	    /* doca mmap for destination buffer */
	struct doca_buf_inventory *buf_inv; /* doca buffer inventory */
	struct doca_ctx *ctx;		    /* doca context */
	struct doca_pe *pe;		    /* doca progress engine */
};

/*
 * Open a DOCA device according to a given PCI address
 *
 * @pci_addr [in]: PCI address
 * @func [in]: pointer to a function that checks if the device have some task capabilities (Ignored if set to NULL)
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_pci(const char *pci_addr, tasks_check func, struct doca_dev **retval);

/*
 * Open a DOCA device according to a given IB device name
 *
 * @value [in]: IB device name
 * @val_size [in]: input length, in bytes
 * @func [in]: pointer to a function that checks if the device have some task capabilities (Ignored if set to NULL)
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_ibdev_name(const uint8_t *value,
					      size_t val_size,
					      tasks_check func,
					      struct doca_dev **retval);

/*
 * Open a DOCA device according to a given interface name
 *
 * @value [in]: interface name
 * @val_size [in]: input length, in bytes
 * @func [in]: pointer to a function that checks if the device have some task capabilities (Ignored if set to NULL)
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_iface_name(const uint8_t *value,
					      size_t val_size,
					      tasks_check func,
					      struct doca_dev **retval);

/*
 * Open a DOCA device with a custom set of capabilities
 *
 * @func [in]: pointer to a function that checks if the device have some task capabilities
 * @retval [out]: pointer to doca_dev struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_with_capabilities(tasks_check func, struct doca_dev **retval);

/*
 * Open a DOCA device representor according to a given VUID string
 *
 * @local [in]: queries representors of the given local doca device
 * @filter [in]: bitflags filter to narrow the representors in the search
 * @value [in]: IB device name
 * @val_size [in]: input length, in bytes
 * @retval [out]: pointer to doca_dev_rep struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_rep_with_vuid(struct doca_dev *local,
					    enum doca_devinfo_rep_filter filter,
					    const uint8_t *value,
					    size_t val_size,
					    struct doca_dev_rep **retval);

/*
 * Open a DOCA device according to a given PCI address
 *
 * @local [in]: queries representors of the given local doca device
 * @filter [in]: bitflags filter to narrow the representors in the search
 * @pci_addr [in]: PCI address
 * @retval [out]: pointer to doca_dev_rep struct, NULL if not found
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_doca_device_rep_with_pci(struct doca_dev *local,
					   enum doca_devinfo_rep_filter filter,
					   const char *pci_addr,
					   struct doca_dev_rep **retval);

/*
 * Initialize a series of DOCA Core objects needed for the program's execution
 *
 * @state [in]: struct containing the set of initialized DOCA Core objects
 * @max_bufs [in]: maximum number of buffers for DOCA Inventory
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_core_objects(struct program_core_objects *state, uint32_t max_bufs);

/*
 * Request to stop context
 *
 * @pe [in]: DOCA progress engine
 * @ctx [in]: DOCA context added to the progress engine
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t request_stop_ctx(struct doca_pe *pe, struct doca_ctx *ctx);

/*
 * Cleanup the series of DOCA Core objects created by create_core_objects
 *
 * @state [in]: struct containing the set of initialized DOCA Core objects
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t destroy_core_objects(struct program_core_objects *state);

/*
 * Create a string Hex dump representation of the given input buffer
 *
 * @data [in]: Pointer to the input buffer
 * @size [in]: Number of bytes to be analyzed
 * @return: pointer to the string representation, or NULL if an error was encountered
 */
char *hex_dump(const void *data, size_t size);

/**
 * This method aligns a uint64 value up
 *
 * @value [in]: value to align up
 * @alignment [in]: alignment value
 * @return: aligned value
 */
uint64_t align_up_uint64(uint64_t value, uint64_t alignment);

/**
 * This method aligns a uint64 value down
 *
 * @value [in]: value to align down
 * @alignment [in]: alignment value
 * @return: aligned value
 */
uint64_t align_down_uint64(uint64_t value, uint64_t alignment);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
