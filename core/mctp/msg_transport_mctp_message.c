// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "mctp_base_protocol.h"
#include "msg_transport_mctp_message.h"
#include "common/unused.h"


int msg_transport_mctp_message_send_request_message (const struct msg_transport *transport,
	struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response)
{
	const struct msg_transport_mctp_message *mctp_message =
		(const struct msg_transport_mctp_message*) transport;
	uint32_t message_type;
	int status;

	if ((mctp_message == NULL) || (request == NULL) || (response == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	status = cmd_interface_protocol_mctp_add_header (mctp_message->protocol,
		mctp_message->message_type, request);
	if (status != 0) {
		return status;
	}

	status = mctp_message->base.next->send_request_message (mctp_message->base.next, request,
		timeout_ms, response);
	if (status != 0) {
		return status;
	}

	status = mctp_message->protocol->base.parse_message (&mctp_message->protocol->base, response,
		&message_type);
	if (status != 0) {
		return status;
	}

	if (message_type != mctp_message->message_type) {
		return MSG_TRANSPORT_UNEXPECTED_RESPONSE;
	}

	return 0;
}

/**
 * Initialize a transport for MCTP messages.  This only handles MCTP message encapsulation.
 * Transport and physical bindings would be a different layer, as would higher order protocols being
 * sent over MCTP.
 *
 * @param mctp_message The MCTP message transport to initialize.
 * @param mctp_transport The MCTP transport layer used to send the messages.
 * @param protocol Protocol handler for MCTP messages.
 * @param message_type The type of messages being sent through this transport.
 *
 * @return 0 if the message transport was initialized successfully or an error code.
 */
int msg_transport_mctp_message_init (struct msg_transport_mctp_message *mctp_message,
	const struct msg_transport *mctp_transport, const struct cmd_interface_protocol_mctp *protocol,
	uint8_t message_type)
{
	int status;

	if ((mctp_message == NULL) || (protocol == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	memset (mctp_message, 0, sizeof (*mctp_message));

	status = msg_transport_intermediate_init (&mctp_message->base, mctp_transport,
		sizeof (struct mctp_base_protocol_message_header));
	if (status == 0) {
		mctp_message->base.base.send_request_message =
			msg_transport_mctp_message_send_request_message;

		mctp_message->protocol = protocol;
		mctp_message->message_type = message_type;
	}

	return status;
}

/**
 * Release the resources used by an MCTP message transport.
 *
 * @param mctp_message The MCTP message transport to release.
 */
void msg_transport_mctp_message_release (const struct msg_transport_mctp_message *mctp_message)
{
	if (mctp_message != NULL) {
		msg_transport_intermediate_release (&mctp_message->base);
	}
}
