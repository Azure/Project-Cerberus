// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "msg_transport_intermediate.h"
#include "common/unused.h"


int msg_transport_intermediate_get_max_message_overhead (const struct msg_transport *transport,
	uint8_t dest_id)
{
	const struct msg_transport_intermediate *intermediate =
		(const struct msg_transport_intermediate*) transport;
	int overhead;

	if (intermediate == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	overhead = intermediate->next->get_max_message_overhead (intermediate->next, dest_id);
	if (ROT_IS_ERROR (overhead)) {
		return overhead;
	}

	return overhead + intermediate->msg_overhead;
}

int msg_transport_intermediate_get_max_message_payload_length (
		const struct msg_transport *transport, uint8_t dest_id)
{
	const struct msg_transport_intermediate *intermediate =
		(const struct msg_transport_intermediate*) transport;
	int payload;

	if (intermediate == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	payload = intermediate->next->get_max_message_payload_length (intermediate->next, dest_id);
	if (ROT_IS_ERROR (payload)) {
		return payload;
	}

	if (payload >= (int) intermediate->msg_overhead) {
		return payload - intermediate->msg_overhead;
	}
	else {
		return 0;
	}
}

int msg_transport_intermediate_get_max_encapsulated_message_length (
		const struct msg_transport *transport, uint8_t dest_id)
{
	const struct msg_transport_intermediate *intermediate =
		(const struct msg_transport_intermediate*) transport;

	if (intermediate == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	/* This layer does not contribute to the maximum encapsulated length, so just return the raw
	 * value from the next layer of the stack. */
	return intermediate->next->get_max_encapsulated_message_length (intermediate->next, dest_id);
}

int msg_transport_intermediate_get_buffer_overhead (const struct msg_transport *transport,
	uint8_t dest_id, size_t length)
{
	const struct msg_transport_intermediate *intermediate =
		(const struct msg_transport_intermediate*) transport;
	int overhead;

	if (intermediate == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	overhead = intermediate->next->get_buffer_overhead (intermediate->next, dest_id, length);
	if (ROT_IS_ERROR (overhead)) {
		return overhead;
	}

	return overhead + intermediate->msg_overhead;
}

/**
 * Initialize an intermediate transport in a protocol stack.  This does not provide a function to
 * handle sending request messages.  This functionality must be provided by the protocol transport
 * being implemented.
 *
 * @param intermediate The intermediate message transport to initialize.
 * @param next_transport The next message transport in the protocol stack.
 * @param msg_overhead The number of extra bytes that will be added to the message as part of
 * request/response handling.
 *
 * @return 0 if the message transport was initialized successfully or an error code.
 */
int msg_transport_intermediate_init (struct msg_transport_intermediate *intermediate,
	const struct msg_transport *next_transport, size_t msg_overhead)
{
	if ((intermediate == NULL) || (next_transport == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	memset (intermediate, 0, sizeof (*intermediate));

	intermediate->base.get_max_message_overhead =
		msg_transport_intermediate_get_max_message_overhead;
	intermediate->base.get_max_message_payload_length =
		msg_transport_intermediate_get_max_message_payload_length;
	intermediate->base.get_max_encapsulated_message_length =
		msg_transport_intermediate_get_max_encapsulated_message_length;
	intermediate->base.get_buffer_overhead = msg_transport_intermediate_get_buffer_overhead;

	intermediate->next = next_transport;
	intermediate->msg_overhead = msg_overhead;

	return 0;
}

/**
 * Release the resources used by an intermediate message transport.
 *
 * @param intermediate The intermediate message transport to release.
 */
void msg_transport_intermediate_release (const struct msg_transport_intermediate *intermediate)
{
	UNUSED (intermediate);
}
