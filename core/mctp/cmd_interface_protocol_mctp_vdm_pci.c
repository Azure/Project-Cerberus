// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <string.h>
#include "cmd_interface_protocol_mctp_vdm_pci.h"
#include "mctp_base_protocol.h"
#include "cmd_interface/cerberus_protocol.h"
#include "common/buffer_util.h"
#include "common/unused.h"


int cmd_interface_protocol_mctp_vdm_pci_parse_message (
	const struct cmd_interface_protocol *protocol, struct cmd_interface_msg *message,
	uint32_t *message_type)
{
	const struct mctp_base_protocol_vdm_pci_header *header;

	if ((protocol == NULL) || (message == NULL) || (message_type == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	if (message->payload_length < sizeof (*header)) {
		return MCTP_BASE_PROTOCOL_MSG_TOO_SHORT;
	}

	header = (const struct mctp_base_protocol_vdm_pci_header*) message->payload;

	if (header->msg_header.msg_type != MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF) {
		return MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG;
	}

	/* Defer protocol header management to protocol handlers specific to the vendor defined
	 * message type. */

	*message_type = buffer_unaligned_read16 (&header->pci_vendor_id);

	return 0;
}

/**
 * Initialize a protocol handler for MCTP Vendor Defined - PCI messages.
 *
 * @param mctp The MCTP handler to initialize.
 *
 * @return 0 if the handler was initialized successfully or an error code.
 */
int cmd_interface_protocol_mctp_vdm_pci_init (struct cmd_interface_protocol_mctp_vdm_pci *mctp)
{
	if (mctp == NULL) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	memset (mctp, 0, sizeof (struct cmd_interface_protocol_mctp_vdm_pci));

	mctp->base.parse_message = cmd_interface_protocol_mctp_vdm_pci_parse_message;

	/* Nothing to do for response handling.  All handling of vendor defined messages needs to be in
	 * a layer specific to that message type. */
	mctp->base.handle_request_result = NULL;

	return 0;
}

/**
 * Release the resources used by an MCTP vendor defined message protocol handler.
 *
 * @param mctp The MCTP handler to release.
 */
void cmd_interface_protocol_mctp_vdm_pci_release (
	const struct cmd_interface_protocol_mctp_vdm_pci *mctp)
{
	UNUSED (mctp);
}
