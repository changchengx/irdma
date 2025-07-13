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

#ifndef COMMON_COMMON_H
#define COMMON_COMMON_H

#include <stdbool.h>

#include <doca_comch.h>
#include <doca_ctx.h>
#include <doca_dev.h>
#include <doca_pe.h>
#include <doca_sync_event.h>

#define SYNC_EVENT_CC_MAX_MSG_SIZE 1024		   /* DOCA comch maximum message size */
#define SYNC_EVENT_CC_MAX_QUEUE_SIZE 8		   /* DOCA comch maximum queue size */
#define SYNC_EVENT_CC_MAX_TASKS 8		   /* DOCA comch maximum send tasks to allocate */
#define SYNC_EVENT_CC_SERVICE_NAME "sync_event_cc" /* DOCA comch service name */
#define SYNC_EVENT_CC_TIMEOUT_SEC 30		   /* DOCA comch timeout in seconds */
#define SYNC_EVENT_CC_ACK_SIZE 1		   /* DOCA comch acknowledge size in bytes */
#define SYNC_EVENT_CC_ACK_VALUE 1		   /* DOCA comch acknowledge value */

/* user input */
struct sync_event_config {
	char dev_pci_addr[DOCA_DEVINFO_PCI_ADDR_SIZE];	   /* Device PCI address */
	char rep_pci_addr[DOCA_DEVINFO_REP_PCI_ADDR_SIZE]; /* DPU representor PCI address */
	bool is_async_mode;	  /* Start DOCA Sync Event in asynchronous or synchronous mode */
	bool is_update_atomic;	  /* Update DOCA Sync Event using Set or atomic Add operation */
	uint32_t async_num_tasks; /* Num tasks for asynchronous mode */
};

/* runtime objects */
struct sync_event_runtime_objects {
	struct doca_dev *dev;	     /* DOCA device */
	struct doca_dev_rep *rep;    /* DOCA representor */
	struct doca_sync_event *se;  /* DOCA Sync Event */
	struct doca_ctx *se_ctx;     /* DOCA Sync Event Context */
	struct doca_pe *se_pe;	     /* DOCA Progress Engine */
	doca_error_t se_task_result; /* Last completed Sync Event Tasks's status */

	/* Comch objects */
	struct doca_pe *comch_pe; /* DOCA Progress Engine for comch */
	union {
		struct doca_comch_server *server; /* Server context (DPU only) */
		struct doca_comch_client *client; /* Client context (x86 host only) */
	};
	struct doca_comch_connection *comch_connection;	    /* Established comch connection */
	doca_comch_event_msg_recv_cb_t comch_recv_event_cb; /* Comch event callback on recv messages */
	void *user_data; /* Sample user data - recv events return struct sync_event_runtime_objects */
};

/*
 * Register command line parameters for DOCA Sync Event sample
 *
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t sync_event_params_register(void);

/*
 * DOCA device with export-to-dpu capability filter callback
 *
 * @devinfo [in]: doca_devinfo
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t sync_event_get_export_to_dpu_supported(struct doca_devinfo *devinfo);

/*
 * Validate configured flow by user input
 *
 * @se_cfg [in]: user configuration represents command line arguments
 * @se_rt_objs [in]: sample's runtime resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t sync_event_config_validate(const struct sync_event_config *se_cfg,
					const struct sync_event_runtime_objects *se_rt_objs);

/*
 * Start Sample's DOCA Sync Event in asynchronous operation mode
 *
 * @se_cfg [in]: user configuration represents command line arguments
 * @se_rt_objs [in]: sample's runtime resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t sync_event_start_async(const struct sync_event_config *se_cfg,
				    struct sync_event_runtime_objects *se_rt_objs);

/*
 * Establish Sample's DOCA comch connection
 *
 * @se_rt_objs [in/out]: sample's runtime resources
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t sync_event_cc_handshake(struct sync_event_runtime_objects *se_rt_objs);

/*
 * Submit asynchronous DOCA Task on Sample's DOCA Sync Event Context
 *
 * @se_rt_objs [in]: sample's runtime resources
 * @se_task [in]: DOCA Task to submit
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
doca_error_t sync_event_async_task_submit(struct sync_event_runtime_objects *se_rt_objs, struct doca_task *se_task);

/*
 * Sample's tear down flow
 *
 * @se_rt_objs [in]: sample's runtime resources
 */
void sync_event_tear_down(struct sync_event_runtime_objects *se_rt_objs);

#endif /* COMMON_COMMON_H */
