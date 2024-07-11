// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_SPDM_PCISIG_STATIC_H_
#define CMD_INTERFACE_PROTOCOL_SPDM_PCISIG_STATIC_H_

#include "cmd_interface_protocol_spdm_pcisig.h"


/* Internal function declarations to allow for static initialization. */
int cmd_interface_protocol_spdm_pcisig_parse_message (const struct cmd_interface_protocol *protocol,
	struct cmd_interface_msg *message, uint32_t *message_type);
int cmd_interface_protocol_spdm_pcisig_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message);

/**
 * Constant initializer for SPDM PCISIG protocol API
 */
#define CMD_INTERFACE_PROTOCOL_SPDM_PCISIG_API_INIT { \
	.parse_message = cmd_interface_protocol_spdm_pcisig_parse_message, \
	.handle_request_result = cmd_interface_protocol_spdm_pcisig_handle_request_result, \
}

/**
 * SPDM PCISIG protocol Static Initialization.
 *
 * There is no validation done on the arguments.
 */
#define cmd_interface_protocol_spdm_pcisig_static_init() { \
	.base = CMD_INTERFACE_PROTOCOL_SPDM_PCISIG_API_INIT, \
}


#endif	/* CMD_INTERFACE_PROTOCOL_SPDM_PCISIG_STATIC_H_ */
