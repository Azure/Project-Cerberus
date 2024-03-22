// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_CERBERUS_H_
#define CMD_INTERFACE_PROTOCOL_CERBERUS_H_

#include "cmd_interface/cmd_interface.h"


/**
 * Protocol handler for Cerberus messages.  Encrypted messages are not supported by this handler.
 */
struct cmd_interface_protocol_cerberus {
	struct cmd_interface_protocol base;			/**< Base protocol handling API. */
};


int cmd_interface_protocol_cerberus_init (struct cmd_interface_protocol_cerberus *cerberus);
void cmd_interface_protocol_cerberus_release (
	const struct cmd_interface_protocol_cerberus *cerberus);

/* Internal functions for use by derived types. */
int cmd_interface_protocol_cerberus_parse_message (const struct cmd_interface_protocol *protocol,
	struct cmd_interface_msg *message, uint32_t *message_type);
int cmd_interface_protocol_cerberus_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message);


#endif /* CMD_INTERFACE_PROTOCOL_CERBERUS_H_ */
