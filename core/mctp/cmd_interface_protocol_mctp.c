// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cmd_interface_protocol_mctp.h"
#include "mctp_base_protocol.h"
#include "common/unused.h"


int cmd_interface_protocol_mctp_parse_message (const struct cmd_interface_protocol *protocol,
	struct cmd_interface_msg *message, uint32_t *message_type)
{
	const struct mctp_base_protocol_message_header *header;

	if ((protocol == NULL) || (message == NULL) || (message_type == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	if (message->payload_length < sizeof (*header)) {
		return MCTP_BASE_PROTOCOL_MSG_TOO_SHORT;
	}

	header = (const struct mctp_base_protocol_message_header*) message->payload;

	if (header->msg_type != MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF) {
		/* No supported standard message types allow message integrity checking and require that the
		 * integrity check bit be set to 0. */
		if (header->integrity_check != 0) {
			return MCTP_BASE_PROTOCOL_INVALID_MSG;
		}

		/* TODO:  MCTP control message structures currently assume presence of the message header,
		 * so it needs to be left in place.  Update MCTP control message handling to remove this
		 * header and eliminate this processing exception here. */
		if (header->msg_type != MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG) {
			cmd_interface_msg_remove_protocol_header (message, sizeof (*header));
		}
	}
	else {
		/* Do not make assumptions about the integrity check requirements or capabilities of vendor
		 * defined messages.  Additionally, don't remove the MCTP message header.  Defer all header
		 * processing to a handler for the vendor message. */
	}

	*message_type = header->msg_type;

	return 0;
}

int cmd_interface_protocol_mctp_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message)
{
	struct mctp_base_protocol_message_header *header;

	if ((protocol == NULL) || (message == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	if (message_type != MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF) {
		/* TODO:  Just like in the pre-processing phase, this exception needs to be eliminated and
		 * the protocol header added back to MCTP control messages. */
		if (message_type != MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG) {
			cmd_interface_msg_add_protocol_header (message, sizeof (*header));
		}

		/* Only update the header in the case of a successful response. */
		if (result == 0) {
			header = (struct mctp_base_protocol_message_header*) message->payload;

			header->msg_type = message_type;
			header->integrity_check = 0;
		}
	}
	else {
		/* Vendor defined protocol processing is assumed to have already been done.  Don't do
		 * anything additional here. */
	}

	/* Since no responses are being generated in this layer, just pass-through the result code. */
	return result;
}

/**
 * Initialize a protocol handler for MCTP messages.
 *
 * @param mctp The MCTP handler to initialize.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_protocol_mctp_init (struct cmd_interface_protocol_mctp *mctp)
{
	if (mctp == NULL) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	memset (mctp, 0, sizeof (struct cmd_interface_protocol_mctp));

	mctp->base.parse_message = cmd_interface_protocol_mctp_parse_message;
	mctp->base.handle_request_result = cmd_interface_protocol_mctp_handle_request_result;

	return 0;
}

/**
 * Release the resources used by an MCTP message protocol handler.
 *
 * @param mctp The MCTP handler to release.
 */
void cmd_interface_protocol_mctp_release (const struct cmd_interface_protocol_mctp *mctp)
{
	UNUSED (mctp);
}
