// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "msg_transport.h"
#include "common/common_math.h"


/**
 * Initialize a message descriptor so it can be used to build a request message to send over a
 * transport.
 *
 * All requests sent by a transport must be created using this function prior to building the
 * request payload.
 *
 * @param transport The transport that will be used to send the request message.
 * @param msg_buffer The buffer that will hold the request.  This must be the beginning of the data
 * buffer to use, without considering any transport encapsulation overhead.
 * @param length The total size of the message buffer.  Since the payload size is not known at this
 * point, the buffer must be at least large enough to fit the maximum transport overhead.
 * @param dest_id Identifier for the intended recipient of the request.  For MCTP transports, this
 * would be the destination EID.
 * @param request Output message descriptor that is being initialized.  Any prior contents will be
 * lost.  The payload and payload_length fields will indicate the buffer to use for building the
 * payload and the maximum amount of payload data that can be sent, respectively.  Prior to sending
 * the request, the payload_length field must be updated with the actual length of the payload data
 * using {@link cmd_interface_msg_set_message_payload_length}.
 *
 * @return 0 if the message descriptor was initialized successfully or an error code.
 */
int msg_transport_create_empty_request (const struct msg_transport *transport, uint8_t *msg_buffer,
	size_t length, uint8_t dest_id, struct cmd_interface_msg *request)
{
	int overhead;
	int max_payload;

	if ((transport == NULL) || (msg_buffer == NULL) || (request == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	overhead = transport->get_buffer_overhead (transport, dest_id, length);
	if (ROT_IS_ERROR (overhead)) {
		return overhead;
	}

	if ((size_t) overhead > length) {
		return MSG_TRANSPORT_OVERHEAD_MORE_THAN_BUFFER;
	}

	max_payload = transport->get_max_message_payload_length (transport, dest_id);
	if (ROT_IS_ERROR (max_payload)) {
		return max_payload;
	}

	memset (request, 0, sizeof (*request));

	request->data = msg_buffer;
	request->max_response = length;
	request->payload = &msg_buffer[overhead];
	request->payload_length = min ((length - overhead), (size_t) max_payload);
	request->target_eid = dest_id;

	return 0;
}

/**
 * Initialize a message descriptor to be used for receiving a response message.
 *
 * @param msg_buffer The buffer that will hold the response.  This must be the beginning of the data
 * buffer to use, without considering any transport encapsulation overhead.
 * @param length The total size of the message buffer.
 * @param response Output message descriptor that is being initialized.  Any prior contents will be
 * lost.
 *
 * @return 0 if the message descriptor was initialized successfully or an error code.
 */
int msg_transport_create_empty_response (uint8_t *msg_buffer, size_t length,
	struct cmd_interface_msg *response)
{
	if ((msg_buffer == NULL) || (response == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	memset (response, 0, sizeof (*response));

	response->data = msg_buffer;
	response->max_response = length;
	response->payload = msg_buffer;

	return 0;
}
