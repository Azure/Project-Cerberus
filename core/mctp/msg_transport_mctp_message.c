// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "msg_transport_mctp_message.h"
#include "common/unused.h"


int msg_transport_mctp_message_get_max_message_overhead (const struct msg_transport *transport,
	uint8_t dest_id)
{
	const struct msg_transport_mctp_message *mctp_message =
		(const struct msg_transport_mctp_message*) transport;
	int overhead;

	if (mctp_message == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	overhead = mctp_message->mctp_transport->get_max_message_overhead (mctp_message->mctp_transport,
		dest_id);
	if (ROT_IS_ERROR (overhead)) {
		return overhead;
	}

	return overhead + sizeof (struct mctp_base_protocol_message_header);
}

int msg_transport_mctp_message_get_max_message_payload_length (
	const struct msg_transport *transport, uint8_t dest_id)
{
	const struct msg_transport_mctp_message *mctp_message =
		(const struct msg_transport_mctp_message*) transport;
	int payload;

	if (mctp_message == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	payload = mctp_message->mctp_transport->get_max_message_payload_length (
		mctp_message->mctp_transport, dest_id);
	if (ROT_IS_ERROR (payload)) {
		return payload;
	}

	if (payload >= (int) sizeof (struct mctp_base_protocol_message_header)) {
		return payload - sizeof (struct mctp_base_protocol_message_header);
	}
	else {
		return 0;
	}
}

int msg_transport_mctp_message_get_max_encapsulated_message_length (
	const struct msg_transport *transport, uint8_t dest_id)
{
	const struct msg_transport_mctp_message *mctp_message =
		(const struct msg_transport_mctp_message*) transport;

	if (mctp_message == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	/* This layer does not contribute to the maximum encapsulated length, so just return the raw
	 * value from the MCTP transport. */
	return mctp_message->mctp_transport->get_max_encapsulated_message_length (
		mctp_message->mctp_transport, dest_id);
}

int msg_transport_mctp_message_get_buffer_overhead (const struct msg_transport *transport,
	uint8_t dest_id, size_t length)
{
	const struct msg_transport_mctp_message *mctp_message =
		(const struct msg_transport_mctp_message*) transport;
	int overhead;

	if (mctp_message == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	overhead = mctp_message->mctp_transport->get_buffer_overhead (mctp_message->mctp_transport,
		dest_id, length);
	if (ROT_IS_ERROR (overhead)) {
		return overhead;
	}

	return overhead + sizeof (struct mctp_base_protocol_message_header);
}

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

	status = mctp_message->mctp_transport->send_request_message (mctp_message->mctp_transport,
		request, timeout_ms, response);
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
	if ((mctp_message == NULL) || (mctp_transport == NULL) || (protocol == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	memset (mctp_message, 0, sizeof (*mctp_message));

	mctp_message->base.get_max_message_overhead =
		msg_transport_mctp_message_get_max_message_overhead;
	mctp_message->base.get_max_message_payload_length =
		msg_transport_mctp_message_get_max_message_payload_length;
	mctp_message->base.get_max_encapsulated_message_length =
		msg_transport_mctp_message_get_max_encapsulated_message_length;
	mctp_message->base.get_buffer_overhead = msg_transport_mctp_message_get_buffer_overhead;
	mctp_message->base.send_request_message = msg_transport_mctp_message_send_request_message;

	mctp_message->mctp_transport = mctp_transport;
	mctp_message->protocol = protocol;
	mctp_message->message_type = message_type;

	return 0;
}

/**
 * Release the resources used by an MCTP message transport.
 *
 * @param mctp_message The MCTP message transport to release.
 */
void msg_transport_mctp_message_release (const struct msg_transport_mctp_message *mctp_message)
{
	UNUSED (mctp_message);
}
