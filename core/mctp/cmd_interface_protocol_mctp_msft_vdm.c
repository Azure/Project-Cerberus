// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cmd_interface_protocol_mctp_msft_vdm.h"
#include "mctp_base_protocol.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cerberus_protocol_required_commands.h"
#include "common/buffer_util.h"
#include "common/unused.h"


int cmd_interface_protocol_mctp_msft_vdm_parse_message (
	const struct cmd_interface_protocol *protocol, struct cmd_interface_msg *message,
	uint32_t *message_type)
{
	const struct mctp_base_protocol_vdm_pci_header *header;
	const struct cerberus_protocol_msft_header *msft_header;

	if ((protocol == NULL) || (message == NULL) || (message_type == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	if (message->payload_length < (sizeof (*header) + sizeof (*msft_header))) {
		return CMD_HANDLER_PAYLOAD_TOO_SHORT;
	}

	header = (const struct mctp_base_protocol_vdm_pci_header*) message->payload;

	if ((header->msg_header.msg_type != MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF) ||
		(header->msg_header.integrity_check == 1) ||
		(buffer_unaligned_read16 (&header->pci_vendor_id) != CERBERUS_PROTOCOL_MSFT_PCI_VID)) {
		return CMD_HANDLER_UNSUPPORTED_MSG;
	}

	/* TODO:  Remove the MCTP header before returning from this protocol layer.  Requires updating
	 * Cerberus message processing. */
	// cmd_interface_msg_remove_protocol_header (message, sizeof (*header));

	msft_header = (const struct cerberus_protocol_msft_header*) &message->payload[sizeof (*header)];

	*message_type = msft_header->rq;

	return 0;
}

int cmd_interface_protocol_mctp_msft_vdm_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message)
{
	struct mctp_base_protocol_vdm_pci_header *header;
	struct cerberus_protocol_msft_header *msft_header;

	if ((protocol == NULL) || (message == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	msft_header = (struct cerberus_protocol_msft_header*) &message->payload[sizeof (*header)];

	/* TODO:  Add the MCTP VDP header in this layer. */
	// cmd_interface_msg_add_protocol_header (message, sizeof (*header));

	/* Only update the header in the case of a successful response. */
	if (result == 0) {
		header = (struct mctp_base_protocol_vdm_pci_header*) message->payload;

		header->msg_header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
		header->msg_header.integrity_check = 0;
		buffer_unaligned_write16 (&header->pci_vendor_id, CERBERUS_PROTOCOL_MSFT_PCI_VID);

		msft_header->rq = message_type;
	}
	else {
		/* TODO:  Generate an error response on failure.  It should not be possible to exit this
		 * handler without a valid response generated.  This impacts error logging in the MCTP
		 * interface, though. */
		// cerberus_protocol_build_error_response (message, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED,
		// 	result, message_type);
	}

	/* TODO:  Eventually, this should always return 0. */
	return result;
}

/**
 * Initialize a protocol handler for Microsoft MCTP vendor defined messages.
 *
 * @param mctp The MCTP handler to initialize.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_protocol_mctp_msft_vdm_init (struct cmd_interface_protocol_mctp_msft_vdm *mctp)
{
	if (mctp == NULL) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (mctp, 0, sizeof (struct cmd_interface_protocol_mctp_msft_vdm));

	mctp->base.parse_message = cmd_interface_protocol_mctp_msft_vdm_parse_message;
	mctp->base.handle_request_result = cmd_interface_protocol_mctp_msft_vdm_handle_request_result;

	return 0;
}

/**
 * Release the resources used by a Microsoft MCTP vendor defined message protocol handler.
 *
 * @param mctp The MCTP handler to release.
 */
void cmd_interface_protocol_mctp_msft_vdm_release (
	const struct cmd_interface_protocol_mctp_msft_vdm *mctp)
{
	UNUSED (mctp);
}
