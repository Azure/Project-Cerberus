// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MSG_TRANSPORT_MCTP_MESSAGE_H_
#define MSG_TRANSPORT_MCTP_MESSAGE_H_

#include "cmd_interface/msg_transport.h"
#include "mctp/cmd_interface_protocol_mctp.h"


/**
 * Defines a transport for sending MCTP messages, irrespective of the physical transport layer used
 * to transmit the message.
 */
struct msg_transport_mctp_message {
	struct msg_transport base;							/**< Base transport API. */
	const struct msg_transport *mctp_transport;			/**< Interface to the MCTP transport layer. */
	const struct cmd_interface_protocol_mctp *protocol;	/**< Protocol handler for MCTP messages. */
	uint8_t message_type;								/**< The type of messages being sent. */
};


int msg_transport_mctp_message_init (struct msg_transport_mctp_message *mctp_message,
	const struct msg_transport *mctp_transport, const struct cmd_interface_protocol_mctp *protocol,
	uint8_t message_type);
void msg_transport_mctp_message_release (const struct msg_transport_mctp_message *mctp_message);


#endif /* MSG_TRANSPORT_MCTP_MESSAGE_H_ */
