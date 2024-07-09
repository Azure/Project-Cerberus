// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_MULTI_HANDLER_STATIC_H_
#define CMD_INTERFACE_MULTI_HANDLER_STATIC_H_

#include "cmd_interface_multi_handler.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_multi_handler_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request);
int cmd_interface_multi_handler_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response);

int cmd_interface_multi_handler_is_message_type_supported (
	const struct cmd_interface_multi_handler *intf, uint32_t message_type);


/**
 * Constant initializer for response handling.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	CMD_INTERFACE_MULTI_HANDLER_RESPONSE_API    \
	.process_response = cmd_interface_multi_handler_process_response,
#else
#define	CMD_INTERFACE_MULTI_HANDLER_RESPONSE_API
#endif

/**
 * Constant initializer for the command interface API.
 */
#define	CMD_INTERFACE_MULTI_HANDLER_API_INIT { \
		.process_request = cmd_interface_multi_handler_process_request, \
		CMD_INTERFACE_MULTI_HANDLER_RESPONSE_API \
		.session = NULL, \
	}


/**
 * Initializes a static instance of a command handler for a specific message type.
 *
 * There is no validation done on the arguments.
 *
 * @param type_id_arg Identifier for the message type.  This must match the message type output from
 * the {@link cmd_interface_protocol.get_message_type} call.
 * @param handler_ptr The command handler to use for processing this type of message.
 */
#define	cmd_interface_multi_handler_msg_type_static_init(type_id_arg, handler_ptr) { \
		.type_id = type_id_arg, \
		.handler = handler_ptr, \
	}

/**
 * Initialize a static instance of a command handler for a protocol that wraps multiple different
 * types of messages that have different processing requirements.
 *
 * There is no validation done on the arguments.
 *
 * @param protocol_ptr Handler for protocol specific details common to all message types.
 * @param msg_types_ptr A list of command handlers for the different message types that are supported.
 * @param type_count_arg The number of supported message types in the list.
 */
#define	cmd_interface_multi_handler_static_init(protocol_ptr, msg_types_ptr, type_count_arg) { \
		.base = CMD_INTERFACE_MULTI_HANDLER_API_INIT, \
		.is_message_type_supported = cmd_interface_multi_handler_is_message_type_supported, \
		.protocol = protocol_ptr, \
		.msg_types = msg_types_ptr, \
		.type_count = type_count_arg, \
	}


#endif	/* CMD_INTERFACE_MULTI_HANDLER_STATIC_H_ */
