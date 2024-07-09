// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_AC_ROT_STATIC_H_
#define CMD_INTERFACE_AC_ROT_STATIC_H_

#include "cmd_interface_ac_rot.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_ac_rot_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);
int cmd_interface_ac_rot_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);


/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_AC_ROT_RESPONSE_API   \
	.process_response = cmd_interface_ac_rot_process_response,
#else
#define	CMD_INTERFACE_AC_ROT_RESPONSE_API
#endif

/**
 * Constant initializer for the command interface API.
 *
 * @param session_ptr Optional handler for channel encryption.
 */
#define	CMD_INTERFACE_AC_ROT_API_INIT(session_ptr) { \
		.process_request = cmd_interface_ac_rot_process_request, \
		CMD_INTERFACE_AC_ROT_RESPONSE_API \
		.session = session_ptr, \
	}


/**
 * Initialize a static instance for a minimal AC-RoT command handler.
 *
 * There is no validation done on the arguments.
 *
 * @param attestation_ptr Handler for attestation requests.
 * @param device_manager_ptr Manager for known devices.
 * @param background_ptr Context for executing long-running operations in the background.
 * @param fw_version_ptr The FW version strings reported by the device.
 * @param riot_ptr Manager for device identity keys.
 * @param cmd_device_ptr Handler for commands that depend on platform details.
 * @param vendor_id_arg Device vendor identifier for the platform.
 * @param device_id_arg Device identifier for the platform.
 * @param subsystem_vid_arg Subsystem vendor identifier for the platform.
 * @param subsystem_id_arg Subsystem identifier for the platform.
 * @param session_ptr Optional handler for channel encryption.
 */
#define	cmd_interface_ac_rot_static_init(attestation_ptr, device_manager_ptr, background_ptr, \
	fw_version_ptr, riot_ptr, cmd_device_ptr, vendor_id_arg, device_id_arg, subsystem_vid_arg, \
	subsystem_id_arg, session_ptr) { \
		.base = CMD_INTERFACE_AC_ROT_API_INIT (session_ptr), \
		.background = background_ptr,\
		.riot = riot_ptr, \
		.attestation = attestation_ptr, \
		.fw_version = fw_version_ptr, \
		.device_manager = device_manager_ptr, \
		.cmd_device = cmd_device_ptr, \
		.device_id = { \
			.vendor_id = vendor_id_arg, \
			.device_id = device_id_arg, \
			.subsystem_vid = subsystem_vid_arg, \
			.subsystem_id = subsystem_id_arg, \
		}, \
	}


#endif	/* CMD_INTERFACE_AC_ROT_STATIC_H_ */
