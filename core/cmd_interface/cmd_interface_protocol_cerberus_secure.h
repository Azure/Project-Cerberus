// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef CMD_INTERFACE_PROTOCOL_CERBERUS_SECURE_H_
#define CMD_INTERFACE_PROTOCOL_CERBERUS_SECURE_H_

#include "cmd_interface/cmd_interface_protocol_cerberus.h"
#include "cmd_interface/session_manager.h"


/**
 * Protocol handler for Cerberus messages.  Both encrypted and unencrypted messages are supported by
 * this handler.
 */
struct cmd_interface_protocol_cerberus_secure {
	struct cmd_interface_protocol_cerberus base;	/**< Base protocol handling API. */
	struct session_manager *session;				/**< The session manager for handling encrypted messages. */
};


int cmd_interface_protocol_cerberus_secure_init (
	struct cmd_interface_protocol_cerberus_secure *cerberus, struct session_manager *session);
void cmd_interface_protocol_cerberus_secure_release (
	const struct cmd_interface_protocol_cerberus_secure *cerberus);


#endif /* CMD_INTERFACE_PROTOCOL_CERBERUS_SECURE_H_ */
