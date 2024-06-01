// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MSG_TRANSPORT_MCTP_MESSAGE_STATIC_H_
#define MSG_TRANSPORT_MCTP_MESSAGE_STATIC_H_

#include "msg_transport_mctp_message.h"


/* Internal functions declared to allow for static initialization. */
int msg_transport_mctp_message_get_max_message_overhead (const struct msg_transport *transport,
	uint8_t dest_id);
int msg_transport_mctp_message_get_max_message_payload_length (
	const struct msg_transport *transport, uint8_t dest_id);
int msg_transport_mctp_message_get_max_encapsulated_message_length (
	const struct msg_transport *transport, uint8_t dest_id);
int msg_transport_mctp_message_get_buffer_overhead (const struct msg_transport *transport,
	uint8_t dest_id, size_t length);
int msg_transport_mctp_message_send_request_message (const struct msg_transport *transport,
	struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response);


/**
 * Constant initializer for the message transport API.
 */
#define	MSG_TRANSPORT_MCTP_MESSAGE_API_INIT { \
		.get_max_message_overhead = msg_transport_mctp_message_get_max_message_overhead, \
		.get_max_message_payload_length = \
			msg_transport_mctp_message_get_max_message_payload_length, \
		.get_max_encapsulated_message_length = \
			msg_transport_mctp_message_get_max_encapsulated_message_length, \
		.get_buffer_overhead = msg_transport_mctp_message_get_buffer_overhead, \
		.send_request_message = msg_transport_mctp_message_send_request_message, \
	}


/**
 * Initialize a static transport for MCTP messages. This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param transport_ptr The MCTP transport layer used to send the messages.
 * @param protocol_ptr Protocol handler for MCTP messages.
 * @param message_type_arg The type of messages being sent through this transport.
 */
#define	msg_transport_mctp_message_static_init(transport_ptr, protocol_ptr, message_type_arg) { \
		.base = MSG_TRANSPORT_MCTP_MESSAGE_API_INIT, \
		.mctp_transport = transport_ptr, \
		.protocol = protocol_ptr, \
		.message_type = message_type_arg, \
	}


#endif /* MSG_TRANSPORT_MCTP_MESSAGE_STATIC_H_ */
