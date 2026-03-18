// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_RMA_STATIC_H_
#define CMD_INTERFACE_RMA_STATIC_H_

#include "cmd_interface_rma.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_rma_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);
int cmd_interface_rma_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);


/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_RMA_RESPONSE_API  \
	.process_response = cmd_interface_rma_process_response,
#else
#define	CMD_INTERFACE_RMA_RESPONSE_API
#endif

/**
 * Constant initializer for the command interface API.
 */
#define	CMD_INTERFACE_RMA_API_INIT	{ \
		.process_request = cmd_interface_rma_process_request, \
		CMD_INTERFACE_RMA_RESPONSE_API \
		.session = NULL, \
	}


/**
 * Initialize a static instance of a minimal command handler to support RMA workflows.
 *
 * There is no validation done on the arguments.
 *
 * @param device_manager_ptr Manager for known devices.
 * @param vendor_id_val Device vendor ID.
 * @param device_id_val Device ID.
 * @param subsystem_vid_val Subsystem vendor ID.
 * @param subsystem_id_val Subsystem ID.
 */
#define	cmd_interface_rma_static_init(device_manager_ptr, vendor_id_val, device_id_val, \
	subsystem_vid_val, subsystem_id_val) { \
		.base = CMD_INTERFACE_RMA_API_INIT, \
		.device_manager = device_manager_ptr, \
		.device_id = { \
			.vendor_id = (vendor_id_val), \
			.device_id = (device_id_val), \
			.subsystem_vid = (subsystem_vid_val), \
			.subsystem_id = (subsystem_id_val), \
		}, \
	}


#endif	/* CMD_INTERFACE_RMA_STATIC_H_ */
