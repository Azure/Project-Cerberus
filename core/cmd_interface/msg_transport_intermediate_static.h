// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MSG_TRANSPORT_INTERMEDIATE_STATIC_H_
#define MSG_TRANSPORT_INTERMEDIATE_STATIC_H_

#include "msg_transport_intermediate.h"


/* Internal functions declared to allow for static initialization. */
int msg_transport_intermediate_get_max_message_overhead (const struct msg_transport *transport,
	uint8_t dest_id);
int msg_transport_intermediate_get_max_message_payload_length (
	const struct msg_transport *transport, uint8_t dest_id);
int msg_transport_intermediate_get_max_encapsulated_message_length (
	const struct msg_transport *transport, uint8_t dest_id);
int msg_transport_intermediate_get_buffer_overhead (const struct msg_transport *transport,
	uint8_t dest_id, size_t length);


/* Internal initializers for use by derived types. */

/**
 * Constant initializer for the message transport API.
 *
 * @param send_func Function to use for sending request messages.
 */
#define	MSG_TRANSPORT_MCTP_MESSAGE_API_INIT(send_func) { \
		.get_max_message_overhead = msg_transport_intermediate_get_max_message_overhead, \
		.get_max_message_payload_length = \
			msg_transport_intermediate_get_max_message_payload_length, \
		.get_max_encapsulated_message_length = \
			msg_transport_intermediate_get_max_encapsulated_message_length, \
		.get_buffer_overhead = msg_transport_intermediate_get_buffer_overhead, \
		.send_request_message = send_func, \
	}


/**
 * Initialize a static transport that is an intermediate layer of a protocol stack. This can be a
 * constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param send_func The function to use for sending request messages.
 * @param next_transport_ptr The next message transport in the protocol stack.
 * @param msg_overhead_arg The number of extra bytes that will be added to the message as part of
 * request/response handling.
 */
#define	msg_transport_intermediate_static_init(send_func, next_transport_ptr, msg_overhead_arg) { \
		.base = MSG_TRANSPORT_MCTP_MESSAGE_API_INIT (send_func), \
		.next = next_transport_ptr, \
		.msg_overhead = msg_overhead_arg, \
	}


#endif /* MSG_TRANSPORT_INTERMEDIATE_STATIC_H_ */
