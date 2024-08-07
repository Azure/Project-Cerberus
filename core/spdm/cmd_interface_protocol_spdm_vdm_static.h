// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_SPDM_VDM_STATIC_H_
#define CMD_INTERFACE_PROTOCOL_SPDM_VDM_STATIC_H_

#include "cmd_interface_protocol_spdm_vdm.h"


/* Internal function declarations to allow for static initialization. */
int cmd_interface_protocol_spdm_vdm_parse_message (const struct cmd_interface_protocol *protocol,
	struct cmd_interface_msg *message, uint32_t *message_type);
int cmd_interface_protocol_spdm_vdm_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message);

/**
 * Constant initializer for SPDM VDM protocol API
 */
#define CMD_INTERFACE_PROTOCOL_SPDM_VDM_API_INIT { \
	.parse_message = cmd_interface_protocol_spdm_vdm_parse_message, \
	.handle_request_result = cmd_interface_protocol_spdm_vdm_handle_request_result, \
}

/**
 * SPDM VDM protocol Static Initialization.
 *
 * There is no validation done on the arguments.
 */
#define cmd_interface_protocol_spdm_vdm_static_init() { \
	.base = CMD_INTERFACE_PROTOCOL_SPDM_VDM_API_INIT, \
}


#endif	/* CMD_INTERFACE_PROTOCOL_SPDM_VDM_STATIC_H_ */
