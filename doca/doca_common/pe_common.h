/*
 * Copyright (c) 2023 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
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

#ifndef PE_COMMON_H_
#define PE_COMMON_H_

#include <doca_ctx.h>
#include <doca_dma.h>

/**
 * This struct defines the program context.
 */
struct pe_sample_state_base {
	/**
	 * Resources
	 */
	struct doca_dev *device;
	struct doca_mmap *mmap;
	struct doca_buf_inventory *inventory;
	struct doca_pe *pe;

	size_t buffer_size;
	size_t buf_inventory_size;

	/**
	 * Buffer
	 * This buffer is used for the source and destination.
	 * Real life scenario may use more memory areas.
	 */
	uint8_t *buffer;
	uint8_t *available_buffer; /* Points to the available location in the buffer, used during initialization */

	/* Common state */
	uint32_t num_completed_tasks;
};

/*
 * Process completed task
 *
 * @dma_task [in]: Completed task
 * @expected_value [in]: Expected value in the destination.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t process_completed_dma_memcpy_task(struct doca_dma_task_memcpy *dma_task, uint8_t expected_value);

/*
 * Free task buffers
 *
 * @dma_task [in]: task
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t free_dma_memcpy_task_buffers(struct doca_dma_task_memcpy *dma_task);

/*
 * Free DMA task
 *
 * @dma_task [in]: task
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t dma_task_free(struct doca_dma_task_memcpy *dma_task);

/**
 * Allocates a buffer that will be used for the source and destination buffers.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t allocate_buffer(struct pe_sample_state_base *state);

/**
 * This method allocate the DMA tasks but does not submit them.
 * This is a sample choice. A task can be submitted immediately after it is allocated.
 *
 * @state [in]: sample state
 * @dma [in]: DMA context to allocate the tasks from
 * @num_tasks [in]: Number of tasks per group
 * @dma_buffer_size [in]: Size of DMA buffer
 * @tasks [in]: tasks to allocate
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t allocate_dma_tasks(struct pe_sample_state_base *state,
				struct doca_dma *dma,
				uint32_t num_tasks,
				size_t dma_buffer_size,
				struct doca_dma_task_memcpy **tasks);

/**
 * This method submits all the tasks (@see allocate_dma_tasks).
 *
 * @num_tasks [in]: Number of tasks per group
 * @tasks [in]: tasks to submit
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t submit_dma_tasks(uint32_t num_tasks, struct doca_dma_task_memcpy **tasks);

/**
 * Opens a device that supports SHA and DMA
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_device(struct pe_sample_state_base *state);

/**
 * Creates a progress engine
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_pe(struct pe_sample_state_base *state);

/**
 * Create MMAP, initialize and start it.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_mmap(struct pe_sample_state_base *state);

/**
 * Create buffer inventory, initialize and start it.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_buf_inventory(struct pe_sample_state_base *state);

/**
 * Poll the PE until all tasks are completed.
 *
 * @state [in]: sample state
 * @num_tasks [in]: number of expected tasks
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t poll_for_completion(struct pe_sample_state_base *state, uint32_t num_tasks);

/**
 * This method cleans up the sample resources in reverse order of their creation.
 * This method does not check for destroy return values for simplify.
 * Real code should check the return value and act accordingly (e.g. if doca_ctx_stop failed with DOCA_ERROR_IN_PROGRESS
 * it means that some contexts are still added or even that there are still in flight tasks in the progress engine).
 *
 * @state [in]: sample state
 */
void pe_sample_base_cleanup(struct pe_sample_state_base *state);

#endif /* PE_COMMON_H_ */
