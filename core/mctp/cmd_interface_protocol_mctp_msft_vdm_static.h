// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_MCTP_MSFT_VDM_STATIC_H_
#define CMD_INTERFACE_PROTOCOL_MCTP_MSFT_VDM_STATIC_H_

#include "cmd_interface_protocol_mctp_msft_vdm.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_protocol_mctp_msft_vdm_parse_message (
	const struct cmd_interface_protocol *protocol, struct cmd_interface_msg *message,
	uint32_t *message_type);
int cmd_interface_protocol_mctp_msft_vdm_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message);


/**
 * Constant initializer for the protocol handler API.
 */
#define	CMD_INTERFACE_PROTOCOL_MCTP_MSFT_VDM_API_INIT { \
		.parse_message = cmd_interface_protocol_mctp_msft_vdm_parse_message, \
		.handle_request_result = cmd_interface_protocol_mctp_msft_vdm_handle_request_result, \
	}


/**
 * Initialize a static protocol handler for Microsoft MCTP vendor defined messages.
 *
 * @param device_mgr_ptr Manager for information about other MCTP endpoints known to the device.
 */
#define	cmd_interface_protocol_mctp_msft_vdm_static_init(device_mgr_ptr) { \
		.base = CMD_INTERFACE_PROTOCOL_MCTP_MSFT_VDM_API_INIT, \
		.device_mgr = device_mgr_ptr, \
	}


#endif /* CMD_INTERFACE_PROTOCOL_MCTP_MSFT_VDM_STATIC_H_ */
