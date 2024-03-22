// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_CERBERUS_SECURE_STATIC_H_
#define CMD_INTERFACE_PROTOCOL_CERBERUS_SECURE_STATIC_H_

#include "cmd_interface_protocol_cerberus_secure.h"


/* Internal functions declared to allow for static initialization. */
int cmd_interface_protocol_cerberus_secure_parse_message (
	const struct cmd_interface_protocol *protocol, struct cmd_interface_msg *message,
	uint32_t *message_type);
int cmd_interface_protocol_cerberus_secure_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message);


/**
 * Constant initializer for the protocol handler API.
 */
#define	CMD_INTERFACE_PROTOCOL_CERBERUS_SECURE_API_INIT { \
		.parse_message = cmd_interface_protocol_cerberus_secure_parse_message, \
		.handle_request_result = cmd_interface_protocol_cerberus_secure_handle_request_result, \
	}


/**
 * Initialize a static protocol handler for Cerberus messages.  The handler supports both encrypted
 * and unencrypted messages.
 *
 * No validation is done on the argument.
 *
 * @param session_ptr The session manager for the handler to use for encrypted messages.
 */
#define	cmd_interface_protocol_cerberus_secure_static_init(session_ptr) { \
		.base = { \
			.base = CMD_INTERFACE_PROTOCOL_CERBERUS_SECURE_API_INIT, \
		}, \
		.session = session_ptr, \
	}


#endif /* CMD_INTERFACE_PROTOCOL_CERBERUS_SECURE_STATIC_H_ */
