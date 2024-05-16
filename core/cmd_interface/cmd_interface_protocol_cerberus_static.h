// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_CERBERUS_STATIC_H_
#define CMD_INTERFACE_PROTOCOL_CERBERUS_STATIC_H_

#include "cmd_interface_protocol_cerberus.h"


/**
 * Constant initializer for the protocol handler API.
 */
#define	CMD_INTERFACE_PROTOCOL_CERBERUS_API_INIT { \
		.parse_message = cmd_interface_protocol_cerberus_parse_message, \
		.handle_request_result = cmd_interface_protocol_cerberus_handle_request_result, \
	}


/**
 * Initialize a static protocol handler for Cerberus messages.  The handler does not have support
 * for encrypted messages.
 */
#define	cmd_interface_protocol_cerberus_static_init { \
		.base = CMD_INTERFACE_PROTOCOL_CERBERUS_API_INIT, \
	}


#endif	/* CMD_INTERFACE_PROTOCOL_CERBERUS_STATIC_H_ */
