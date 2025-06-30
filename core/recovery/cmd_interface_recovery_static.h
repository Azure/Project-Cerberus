// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_RECOVERY_STATIC_H_
#define CMD_INTERFACE_RECOVERY_STATIC_H_

#include "cmd_interface_recovery.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_recovery_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);

int cmd_interface_recovery_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);


/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_RECOVERY_RESPONSE_API \
	.process_response = cmd_interface_recovery_process_response,
#else
#define	CMD_INTERFACE_RECOVERY_RESPONSE_API
#endif

/**
 * Constant initializer for the command interface API.
 */
#define	CMD_INTERFACE_RECOVERY_API_INIT	{ \
		.process_request = cmd_interface_recovery_process_request, \
		CMD_INTERFACE_RECOVERY_RESPONSE_API \
	}


/**
 * Initialize a static instance of a minimal command handler to support RECOVERY workflows.
 *
 * There is no validation done on the arguments.
 *
 * @param device_manager_ptr Manager for known devices.
 */
#define	cmd_interface_recovery_static_init(device_manager_ptr, firmware_update_control_ptr, \
	fw_version_ptr,	vendor_id_arg, device_id_arg, subsystem_vid_arg, subsystem_id_arg, \
	attestation_ptr, riot_ptr, background_ptr, cmd_device_ptr) { \
		.base = CMD_INTERFACE_RECOVERY_API_INIT, \
		.device_manager = device_manager_ptr, \
		.control = firmware_update_control_ptr, \
		.fw_version = fw_version_ptr,\
		.background = background_ptr,\
		.riot = riot_ptr, \
		.attestation = attestation_ptr, \
		.cmd_device = cmd_device_ptr, \
		.device_id = { \
			.vendor_id = vendor_id_arg, \
			.device_id = device_id_arg, \
			.subsystem_vid = subsystem_vid_arg, \
			.subsystem_id = subsystem_id_arg, \
		}, \
	}


#endif	/* CMD_INTERFACE_RECOVERY_STATIC_H_ */
