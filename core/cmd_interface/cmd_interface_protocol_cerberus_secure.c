// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cerberus_protocol.h"
#include "cerberus_protocol_required_commands.h"
#include "cmd_interface_protocol_cerberus_secure.h"
#include "common/buffer_util.h"
#include "common/unused.h"


int cmd_interface_protocol_cerberus_secure_parse_message (
	const struct cmd_interface_protocol *protocol, struct cmd_interface_msg *message,
	uint32_t *message_type)
{
	const struct cmd_interface_protocol_cerberus_secure *cerberus =
		(const struct cmd_interface_protocol_cerberus_secure*) protocol;
	const struct cerberus_protocol_header *header;
	int status;

	status = cmd_interface_protocol_cerberus_parse_message (protocol, message, message_type);

	if (status == CMD_HANDLER_ENCRYPTION_UNSUPPORTED) {
		/* The message is otherwise valid, but is encrypted. */
		status = cerberus->session->decrypt_message (cerberus->session, message);
		if (status != 0) {
			return status;
		}

		header = (const struct cerberus_protocol_header*) message->payload;

		/* TODO:  As in the base Cerberus handler, remove the Cerberus protocol header from the
		 * payload. */

		message->max_response -= SESSION_MANAGER_TRAILER_LEN;
		message->is_encrypted = true;

		*message_type = header->command;
		status = 0;
	}

	return status;
}

int cmd_interface_protocol_cerberus_secure_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message)
{
	const struct cmd_interface_protocol_cerberus_secure *cerberus =
		(const struct cmd_interface_protocol_cerberus_secure*) protocol;
	struct cerberus_protocol_header *header;
	int status;

	status = cmd_interface_protocol_cerberus_handle_request_result (protocol, result, message_type,
		message);

	if ((status == 0) && message->is_encrypted) {
		/* The request was encrypted, so encrypt the response. */
		message->max_response += SESSION_MANAGER_TRAILER_LEN;

		status = cerberus->session->encrypt_message (cerberus->session, message);
		if (status != 0) {
			/* Failed to encrypt the message, so whatever response was previously generated is no
			 * longer valid. */
			return status;
		}

		/* TODO:  Deal with the base Cerberus handler adding payload header. */
		header = (struct cerberus_protocol_header*) message->payload;

		header->crypt = 1;
	}

	return status;
}

/**
 * Initialize a protocol handler for Cerberus messages.  The handler supports both encrypted and
 * unencrypted messages.
 *
 * @param cerberus The Cerberus handler to initialize.
 * @param session The session manager for the handler to use for encrypted messages.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_protocol_cerberus_secure_init (
	struct cmd_interface_protocol_cerberus_secure *cerberus, struct session_manager *session)
{
	if ((cerberus == NULL) || (session == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (cerberus, 0, sizeof (struct cmd_interface_protocol_cerberus_secure));

	cerberus->base.base.parse_message = cmd_interface_protocol_cerberus_secure_parse_message;
	cerberus->base.base.handle_request_result =
		cmd_interface_protocol_cerberus_secure_handle_request_result;

	cerberus->session = session;

	return 0;
}

/**
 * Release the resources used by a Cerberus message protocol handler.
 *
 * @param cerberus The Cerberus handler to release.
 */
void cmd_interface_protocol_cerberus_secure_release (
	const struct cmd_interface_protocol_cerberus_secure *cerberus)
{
	UNUSED (cerberus);
}
