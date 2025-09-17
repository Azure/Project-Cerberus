// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "mctp_base_protocol.h"
#include "msg_transport_mctp_vdm_pci.h"
#include "common/unused.h"


int msg_transport_mctp_vdm_pci_send_request_message (const struct msg_transport *transport,
	struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response)
{
	const struct msg_transport_mctp_vdm_pci *mctp_vdm_pci =
		(const struct msg_transport_mctp_vdm_pci*) transport;
	uint32_t message_type;
	int status;

	if ((mctp_vdm_pci == NULL) || (request == NULL) || (response == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	status = cmd_interface_protocol_mctp_vdm_pci_add_header (mctp_vdm_pci->protocol,
		mctp_vdm_pci->vendor_id, request);
	if (status != 0) {
		return status;
	}

	status = mctp_vdm_pci->base.next->send_request_message (mctp_vdm_pci->base.next, request,
		timeout_ms, response);
	if (status != 0) {
		return status;
	}

	status = mctp_vdm_pci->protocol->base.parse_message (&mctp_vdm_pci->protocol->base, response,
		&message_type);
	if (status != 0) {
		return status;
	}

	if (message_type != mctp_vdm_pci->vendor_id) {
		return MSG_TRANSPORT_UNEXPECTED_RESPONSE;
	}

	/* The MCTP VDM protocol handler does not normally remove the header from the payload.  Remove
	 * the header when using this transport. */
	cmd_interface_msg_remove_protocol_header (response,
		sizeof (struct mctp_base_protocol_vdm_pci_header));

	return 0;
}

/**
 * Initialize a transport for MCTP Vendor Defined - PCI messages.  This only handles MCTP message
 * encapsulation for VDMs, including the MCTP message type.  Transport and physical bindings would
 * be a different layer, as would higher order protocols being sent over MCTP VDM.
 *
 * @param mctp_vdm_pci The MCTP VDM transport to initialize.
 * @param mctp_transport The MCTP transport layer used to send the messages.
 * @param protocol Protocol handler for MCTP messages.
 * @param vendor_id Identifier for the vendor defined protocol sent through this transport.
 *
 * @return 0 if the message transport was initialized successfully or an error code.
 */
int msg_transport_mctp_vdm_pci_init (struct msg_transport_mctp_vdm_pci *mctp_vdm_pci,
	const struct msg_transport *mctp_transport,
	const struct cmd_interface_protocol_mctp_vdm_pci *protocol, uint16_t vendor_id)
{
	int status;

	if ((mctp_vdm_pci == NULL) || (protocol == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	memset (mctp_vdm_pci, 0, sizeof (*mctp_vdm_pci));

	status = msg_transport_intermediate_init (&mctp_vdm_pci->base, mctp_transport,
		sizeof (struct mctp_base_protocol_vdm_pci_header));
	if (status == 0) {
		mctp_vdm_pci->base.base.send_request_message =
			msg_transport_mctp_vdm_pci_send_request_message;

		mctp_vdm_pci->protocol = protocol;
		mctp_vdm_pci->vendor_id = vendor_id;
	}

	return status;
}

/**
 * Release the resources used by an MCTP Vendor Defined - PCI message transport.
 *
 * @param mctp_vdm_pci The MCTP message transport to release.
 */
void msg_transport_mctp_vdm_pci_release (const struct msg_transport_mctp_vdm_pci *mctp_vdm_pci)
{
	if (mctp_vdm_pci != NULL) {
		msg_transport_intermediate_release (&mctp_vdm_pci->base);
	}
}
