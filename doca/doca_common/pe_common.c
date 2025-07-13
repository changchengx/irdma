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

#include <unistd.h>
#include <time.h>

#include <doca_log.h>
#include <doca_mmap.h>
#include <doca_buf.h>
#include <doca_buf_inventory.h>
#include <doca_ctx.h>
#include <doca_types.h>
#include <doca_dma.h>
#include <doca_pe.h>

#include <samples/common.h>
#include "pe_common.h"

DOCA_LOG_REGISTER(PE::COMMON);

/**
 * This macro is used to minimize code size.
 * The macro runs an expression and returns error if the expression status is not DOCA_SUCCESS
 */
#define EXIT_ON_FAILURE(_expression_) \
	{ \
		doca_error_t _status_ = _expression_; \
\
		if (_status_ != DOCA_SUCCESS) { \
			DOCA_LOG_ERR("%s failed with status %s", __func__, doca_error_get_descr(_status_)); \
			return _status_; \
		} \
	}

/*
 * Process completed task
 *
 * @details This function verifies that the destination buffer contains the expected value.
 *
 * @dma_task [in]: Completed task
 * @expected_value [in]: Expected value in the destination.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t process_completed_dma_memcpy_task(struct doca_dma_task_memcpy *dma_task, uint8_t expected_value)
{
	const struct doca_buf *dest = doca_dma_task_memcpy_get_dst(dma_task);
	uint8_t *dst = NULL;
	size_t dst_len = 0;
	size_t i = 0;

	EXIT_ON_FAILURE(doca_buf_get_data(dest, (void **)&dst));
	EXIT_ON_FAILURE(doca_buf_get_len(dest, &dst_len));

	for (i = 0; i < dst_len; i++) {
		if (dst[i] != expected_value) {
			DOCA_LOG_ERR("Memcpy failed: Expected %d, received %d at index %zu", expected_value, dst[i], i);
			return DOCA_ERROR_INVALID_VALUE;
		}
	}

	return DOCA_SUCCESS;
}

/*
 * Free task buffers
 *
 * @details This function releases source and destination buffers that are set to a DMA memcpy task.
 *
 * @dma_task [in]: task
 */
doca_error_t free_dma_memcpy_task_buffers(struct doca_dma_task_memcpy *dma_task)
{
	const struct doca_buf *src = doca_dma_task_memcpy_get_src(dma_task);
	struct doca_buf *dst = doca_dma_task_memcpy_get_dst(dma_task);

	/**
	 * Removing the const is fine in this case because the sample owns the buffer and the task is about to be freed.
	 * However, in other cases this action may not be valid.
	 */
	EXIT_ON_FAILURE(doca_buf_dec_refcount((struct doca_buf *)src, NULL));
	EXIT_ON_FAILURE(doca_buf_dec_refcount(dst, NULL));

	return DOCA_SUCCESS;
}

doca_error_t dma_task_free(struct doca_dma_task_memcpy *dma_task)
{
	/**
	 * A DOCA task should be freed once it is no longer used. It can be freed during a completion or error callback,
	 * during the progress one loop (e.g. if the program stores it in the state), at the end of the program,
	 * etc., as long as it is not required anymore.
	 * The sample also releases the buffers during this call, but only for simplicity. Buffers don't have to be
	 * released when a task is released.
	 */

	EXIT_ON_FAILURE(free_dma_memcpy_task_buffers(dma_task));

	doca_task_free(doca_dma_task_memcpy_as_task(dma_task));

	return DOCA_SUCCESS;
}

/**
 * Allocates a buffer that will be used for the source and destination buffers.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t allocate_buffer(struct pe_sample_state_base *state)
{
	DOCA_LOG_INFO("Allocating buffer with size of %zu", state->buffer_size);

	state->buffer = (uint8_t *)malloc(state->buffer_size);
	if (state->buffer == NULL)
		return DOCA_ERROR_NO_MEMORY;

	state->available_buffer = state->buffer;

	return DOCA_SUCCESS;
}

/**
 * This method allocate the DMA tasks but does not submit them.
 * This is a sample choice. A task can be submitted immediately after it is allocated.
 *
 * @state [in]: sample state
 * @dma [in] DMA context to allocate the tasks from.
 * @num_tasks [in]: Number of tasks per group
 * @dma_buffer_size [in]: Size of DMA buffer
 * @tasks [in]: tasks to allocate
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t allocate_dma_tasks(struct pe_sample_state_base *state,
				struct doca_dma *dma,
				uint32_t num_tasks,
				size_t dma_buffer_size,
				struct doca_dma_task_memcpy **tasks)
{
	uint32_t task_id = 0;

	DOCA_LOG_INFO("Allocating tasks");

	for (task_id = 0; task_id < num_tasks; task_id++) {
		struct doca_buf *source = NULL;
		struct doca_buf *destination = NULL;
		union doca_data user_data = {0};

		/* User data will be used to verify copy content */
		user_data.u64 = (task_id + 1);

		/* Use doca_buf_inventory_buf_get_by_data to initialize the source buffer */
		EXIT_ON_FAILURE(doca_buf_inventory_buf_get_by_data(state->inventory,
								   state->mmap,
								   state->available_buffer,
								   dma_buffer_size,
								   &source));

		memset(state->available_buffer, (task_id + 1), dma_buffer_size);
		state->available_buffer += dma_buffer_size;

		/**
		 * Using doca_buf_inventory_buf_get_by_addr leaves the buffer head uninitialized. The DMA context will
		 * set the head and length at the task completion.
		 */
		EXIT_ON_FAILURE(doca_buf_inventory_buf_get_by_addr(state->inventory,
								   state->mmap,
								   state->available_buffer,
								   dma_buffer_size,
								   &destination));

		memset(state->available_buffer, 0, dma_buffer_size);
		state->available_buffer += dma_buffer_size;

		EXIT_ON_FAILURE(doca_dma_task_memcpy_alloc_init(dma, source, destination, user_data, &tasks[task_id]));
	}

	return DOCA_SUCCESS;
}

/**
 * This method submits all the tasks (@see allocate_dma_tasks).
 *
 * @num_tasks [in]: Number of tasks per group
 * @dma_buffer_size [in]: Size of DMA buffer
 * @tasks [in]: tasks to submit
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t submit_dma_tasks(uint32_t num_tasks, struct doca_dma_task_memcpy **tasks)
{
	uint32_t task_id = 0;

	DOCA_LOG_INFO("Submitting tasks");

	for (task_id = 0; task_id < num_tasks; task_id++)
		EXIT_ON_FAILURE(doca_task_submit(doca_dma_task_memcpy_as_task(tasks[task_id])));

	return DOCA_SUCCESS;
}

/*
 * Check if DOCA device is DMA capable
 *
 * @devinfo [in]: Device to check
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t check_dev_dma_capable(struct doca_devinfo *devinfo)
{
	doca_error_t status = doca_dma_cap_task_memcpy_is_supported(devinfo);

	if (status != DOCA_SUCCESS)
		return status;

	return DOCA_SUCCESS;
}

/**
 * Opens a device that supports SHA and DMA
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t open_device(struct pe_sample_state_base *state)
{
	DOCA_LOG_INFO("Opening device");

	EXIT_ON_FAILURE(open_doca_device_with_capabilities(check_dev_dma_capable, &state->device));

	return DOCA_SUCCESS;
}

/**
 * Creates a progress engine
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_pe(struct pe_sample_state_base *state)
{
	DOCA_LOG_INFO("Creating PE");

	EXIT_ON_FAILURE(doca_pe_create(&state->pe));

	return DOCA_SUCCESS;
}

/**
 * Create MMAP, initialize and start it.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_mmap(struct pe_sample_state_base *state)
{
	DOCA_LOG_INFO("Creating MMAP");

	EXIT_ON_FAILURE(doca_mmap_create(&state->mmap));
	EXIT_ON_FAILURE(doca_mmap_set_memrange(state->mmap, state->buffer, state->buffer_size));
	EXIT_ON_FAILURE(doca_mmap_add_dev(state->mmap, state->device));
	EXIT_ON_FAILURE(doca_mmap_set_permissions(state->mmap, DOCA_ACCESS_FLAG_LOCAL_READ_WRITE));
	EXIT_ON_FAILURE(doca_mmap_start(state->mmap));

	return DOCA_SUCCESS;
}

/**
 * Create buffer inventory, initialize and start it.
 *
 * @state [in]: sample state
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t create_buf_inventory(struct pe_sample_state_base *state)
{
	DOCA_LOG_INFO("Creating buf inventory");

	EXIT_ON_FAILURE(doca_buf_inventory_create(state->buf_inventory_size, &state->inventory));
	EXIT_ON_FAILURE(doca_buf_inventory_start(state->inventory));

	return DOCA_SUCCESS;
}

/**
 * This method cleans up the sample resources in reverse order of their creation.
 * This method does not check for destroy return values for simplify.
 * Real code should check the return value and act accordingly (e.g. if doca_ctx_stop failed with DOCA_ERROR_IN_PROGRESS
 * it means that some contexts are still added or even that there are still in flight tasks in the progress engine).
 * @state [in]: sample state
 */
void pe_sample_base_cleanup(struct pe_sample_state_base *state)
{
	if (state->pe != NULL)
		(void)doca_pe_destroy(state->pe);

	if (state->inventory != NULL) {
		(void)doca_buf_inventory_stop(state->inventory);
		(void)doca_buf_inventory_destroy(state->inventory);
	}

	if (state->mmap != NULL) {
		(void)doca_mmap_stop(state->mmap);
		(void)doca_mmap_destroy(state->mmap);
	}

	if (state->device != NULL)
		(void)doca_dev_close(state->device);

	if (state->buffer != NULL)
		free(state->buffer);
}

/**
 * Poll the PE until all tasks are completed.
 *
 * @state [in]: sample state
 * @num_tasks [in] number of expected tasks
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t poll_for_completion(struct pe_sample_state_base *state, uint32_t num_tasks)
{
	DOCA_LOG_INFO("Polling until all tasks are completed");

	/* This loop ticks the progress engine */
	while (state->num_completed_tasks < num_tasks) {
		/**
		 * doca_pe_progress shall return 1 if a task was completed and 0 if not. In this case the sample
		 * does not have anything to do with the return value because it is a polling sample.
		 */
		(void)doca_pe_progress(state->pe);
	}

	DOCA_LOG_INFO("All tasks are completed");

	return DOCA_SUCCESS;
}
