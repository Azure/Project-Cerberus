// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_DUAL_CMD_SET_STATIC_H_
#define CMD_INTERFACE_DUAL_CMD_SET_STATIC_H_

#include "cmd_interface_dual_cmd_set.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_dual_cmd_set_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);
int cmd_interface_dual_cmd_set_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);
int cmd_interface_dual_cmd_set_generate_error_packet (const struct cmd_interface *intf,
	struct cmd_interface_msg *request, uint8_t error_code, uint32_t error_data, uint8_t cmd_set);


/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_DUAL_CMD_SET_RESPONSE_API \
	.process_response = cmd_interface_dual_cmd_set_process_response,
#else
#define	CMD_INTERFACE_DUAL_CMD_SET_RESPONSE_API
#endif

/**
 * Constant initializer for the command interface API.
 */
#define	CMD_INTERFACE_DUAL_CMD_SET_API_INIT { \
		.process_request = cmd_interface_dual_cmd_set_process_request, \
		CMD_INTERFACE_DUAL_CMD_SET_RESPONSE_API \
		.generate_error_packet = cmd_interface_dual_cmd_set_generate_error_packet, \
		.session = NULL, \
	}


/**
 * Initialize a static instance of a command handler with two command sets supported. Requests from
 * each command set get routed to the appropiate command interface. Issuing requests from this
 * interface defaults to the first command set.
 *
 * There is no validation done on the arguments.
 *
 * @param intf_0_ptr The command interface to utilize for command set 0
 * @param intf_1_ptr The command interface to utilize for command set 1
 */
#define	cmd_interface_dual_cmd_set_static_init(intf_0_ptr, intf_1_ptr) { \
		.base = CMD_INTERFACE_DUAL_CMD_SET_API_INIT, \
		.intf_0 = intf_0_ptr, \
		.intf_1 = intf_1_ptr, \
	}


#endif	/* CMD_INTERFACE_DUAL_CMD_SET_STATIC_H_ */
