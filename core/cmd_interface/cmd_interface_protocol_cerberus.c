// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cerberus_protocol.h"
#include "cerberus_protocol_required_commands.h"
#include "cmd_interface_protocol_cerberus.h"
#include "common/buffer_util.h"
#include "common/unused.h"


int cmd_interface_protocol_cerberus_parse_message (const struct cmd_interface_protocol *protocol,
	struct cmd_interface_msg *message, uint32_t *message_type)
{
	const struct cerberus_protocol_header *header;

	if (message == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	message->crypto_timeout = false;

	if ((protocol == NULL) || (message_type == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (message->payload_length < sizeof (*header)) {
		return CMD_HANDLER_PAYLOAD_TOO_SHORT;
	}

	header = (const struct cerberus_protocol_header*) message->payload;

	/* TODO:  These are redundant checks that are done in the MCTP layers, but until those headers
	 * are removed before this layer of processing, this check will remain. */
	if ((header->msg_type != MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF) ||
		(header->integrity_check == 1) ||
		(buffer_unaligned_read16 (&header->pci_vendor_id) != CERBERUS_PROTOCOL_MSFT_PCI_VID)) {
		return CMD_HANDLER_UNSUPPORTED_MSG;
	}

	if ((header->reserved1 != 0) || (header->reserved2 != 0)) {
		return CMD_HANDLER_RSVD_NOT_ZERO;
	}

	/* Encrypted messages are not supported by this handler.  This check is last to allow easy
	 * re-use by a secure protocol handler. */
	if (header->crypt == 1) {
		return CMD_HANDLER_ENCRYPTION_UNSUPPORTED;
	}

	/* TODO:  Remove the Cerberus protocol header from the payload.  This requires the rest of the
	 * command processing stack to align with the change.  The command code would need to be removed
	 * from the header definition. */

	message->is_encrypted = false;

	*message_type = header->command;

	return 0;
}

int cmd_interface_protocol_cerberus_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message)
{
	struct cerberus_protocol_header *header;

	if ((protocol == NULL) || (message == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	/* TODO:  Just like in the pre-processing case, a Cerberus header should be added to the payload
	 * rather than leaving the payload pointer in the same place. */

	header = (struct cerberus_protocol_header*) message->payload;

	/* Only update the header in the case of a successful response. */
	if (result == 0) {
		/* If the handler did not generate any response payload, create a status response indicating
		 * that the command completed successfully.  The rq bit from the request is used to
		 * determine what value to set in the response.
		 *
		 * This checks both payload and data lengths to cover command handlers that don't correctly
		 * update the payload length. */
		if ((message->payload_length == 0) || (message->length == 0)) {
			cerberus_protocol_build_error_response (message, CERBERUS_PROTOCOL_NO_ERROR, 0,
				header->rq, 0);
		}
		else {
			/* TODO:  These are MCTP components and should be updated by MCTP protocol handlers
			 * rather then here.  These will eventually be removed. */
			header->msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
			header->integrity_check = 0;
			buffer_unaligned_write16 (&header->pci_vendor_id, CERBERUS_PROTOCOL_MSFT_PCI_VID);

			/* Leave the rq bit unchanged while populating the header as this layer does not have
			 * context about what it should be for this message. */
			header->reserved1 = 0;
			header->crypt = 0;
			header->reserved2 = 0;
			header->command = message_type;
		}
	}
	else {
		/* Generate an error response on failure.  It should not be possible to exit this handler
		 * without a valid response generated.  Use the request header data, which should not have
		 * been modified by this point to determine the rq bit value for the response. */
		cerberus_protocol_build_error_response (message, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED,
			result, header->rq, message_type);
	}

	/* There will always be a response populated when exiting. */
	return 0;
}

/**
 * Initialize a protocol handler for Cerberus messages.  The handler does not have support for
 * encrypted messages.
 *
 * @param cerberus The Cerberus handler to initialize.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_protocol_cerberus_init (struct cmd_interface_protocol_cerberus *cerberus)
{
	if (cerberus == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (cerberus, 0, sizeof (struct cmd_interface_protocol_cerberus));

	cerberus->base.parse_message = cmd_interface_protocol_cerberus_parse_message;
	cerberus->base.handle_request_result = cmd_interface_protocol_cerberus_handle_request_result;

	return 0;
}

/**
 * Release the resources used by a Cerberus message protocol handler.
 *
 * @param cerberus The Cerberus handler to release.
 */
void cmd_interface_protocol_cerberus_release (
	const struct cmd_interface_protocol_cerberus *cerberus)
{
	UNUSED (cerberus);
}
