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
	const struct cmd_interface_protocol_mctp_msft_vdm *mctp =
		(const struct cmd_interface_protocol_mctp_msft_vdm*) protocol;
	const struct mctp_base_protocol_vdm_pci_header *header;
	const struct cerberus_protocol_msft_header *msft_header;

	if ((mctp == NULL) || (message == NULL) || (message_type == NULL)) {
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

	cmd_interface_msg_set_max_response (message,
		device_manager_get_max_message_len_by_eid (mctp->device_mgr, message->source_eid));

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

	/* TODO:  Add the MCTP VDM header in this layer. */
	// cmd_interface_msg_add_protocol_header (message, sizeof (*header));

	/* Only update the header in the case of a successful response. */
	if (result == 0) {
		if ((message->payload_length == 0) || (message->length == 0)) {
			/* If the handler did not generate any response payload, create a Cerberus status
			 * response indicating that the command completed successfully.  There must always be a
			 * response payload when exiting this layer.
			 *
			 * TODO:  This logic is duplicated from cmd_interface_protocol_cerberus.  It should
			 * really be removed from here and only exist in that handler. */
			cerberus_protocol_build_error_response (message, CERBERUS_PROTOCOL_NO_ERROR, 0,
				message_type, 0);
		}
		else {
			header = (struct mctp_base_protocol_vdm_pci_header*) message->payload;

			header->msg_header.msg_type = MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF;
			header->msg_header.integrity_check = 0;
			buffer_unaligned_write16 (&header->pci_vendor_id, CERBERUS_PROTOCOL_MSFT_PCI_VID);

			msft_header->rq = message_type;
		}
	}
	else {
		/* No errors can escape this layer.  There must always be a response available.  If upper
		 * layers did not generate any kind of response, a Cerberus error message will be
		 * created and logged.
		 *
		 * TODO:  Currently assume the request buffer hasn't been changed by the failure.  Ideally,
		 * the command code would be set to 0 here, since it's not known at this layer, and this
		 * level of detail would be left to the cmd_interface_protocol_cerberus handler. */
		cerberus_protocol_build_error_response (message, CERBERUS_PROTOCOL_ERROR_UNSPECIFIED,
			result, message_type, msft_header->command);
	}

	/* There will always be a response populated when exiting. */
	return 0;
}

/**
 * Initialize a protocol handler for Microsoft MCTP vendor defined messages.
 *
 * @param mctp The MCTP handler to initialize.
 * @param device_mgr Manager for information about other MCTP endpoints known to the device.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_protocol_mctp_msft_vdm_init (struct cmd_interface_protocol_mctp_msft_vdm *mctp,
	struct device_manager *device_mgr)
{
	if ((mctp == NULL) || (device_mgr == NULL)) {
		return CMD_HANDLER_INVALID_ARGUMENT;
	}

	memset (mctp, 0, sizeof (struct cmd_interface_protocol_mctp_msft_vdm));

	mctp->base.parse_message = cmd_interface_protocol_mctp_msft_vdm_parse_message;
	mctp->base.handle_request_result = cmd_interface_protocol_mctp_msft_vdm_handle_request_result;

	mctp->device_mgr = device_mgr;

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
