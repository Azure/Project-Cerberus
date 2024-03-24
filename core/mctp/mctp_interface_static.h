// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_INTERFACE_STATIC_H_
#define MCTP_INTERFACE_STATIC_H_

#include "mctp_interface.h"


/* Internal functions declared to allow for static initialization. */
int mctp_interface_get_max_message_overhead (const struct msg_transport *transport,
	uint8_t dest_id);
int mctp_interface_get_max_message_payload_length (const struct msg_transport *transport,
	uint8_t dest_id);
int mctp_interface_get_max_encapsulated_message_length (const struct msg_transport *transport,
	uint8_t dest_id);
int mctp_interface_get_buffer_overhead (const struct msg_transport *transport, uint8_t dest_id,
	size_t max_message);
int mctp_interface_send_request_message (const struct msg_transport *transport,
	struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response);


/**
 * Constant initializer for the request message transport API.
 */
#define	MCTP_INTERFACE_MSG_TRANSPORT_API_INIT	{ \
		.get_max_message_overhead = mctp_interface_get_max_message_overhead, \
		.get_max_message_payload_length = mctp_interface_get_max_message_payload_length, \
		.get_max_encapsulated_message_length = mctp_interface_get_max_encapsulated_message_length, \
		.get_buffer_overhead = mctp_interface_get_buffer_overhead, \
		.send_request_message = mctp_interface_send_request_message, \
	}

/**
 * Initializer for fields only available when issuing requests is supported.
 */
#ifdef CMD_ENABLE_ISSUE_REQUEST
#define	MCTP_INTERFACE_ISSUE_REQUEST_INIT(channel_ptr, cmd_mctp_ptr, cmd_spdm_ptr)	\
	.base = MCTP_INTERFACE_MSG_TRANSPORT_API_INIT, \
	.channel = channel_ptr, \
	.cmd_mctp = cmd_mctp_ptr, \
	.cmd_spdm = cmd_spdm_ptr,
#else
#define	MCTP_INTERFACE_ISSUE_REQUEST_INIT(channel_ptr, cmd_mctp_ptr, cmd_spdm_ptr)
#endif

/**
 * Initialize a static instance of an MCTP message handler. This can be a constant instance.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the MCTP message handler.
 * @param req_handler_ptr The handler to call processing a received MCTP request message.  This
 * handler will be called irrespective of the message type.
 * @param device_mgr_ptr The device manager linked to command interface.
 * @param channel_ptr The channel to use for sending request messages.  This can be null if sending
 * requests is not necessary.
 * @param cmd_cerberus_ptr The command interface for legacy processing of Cerberus response
 * messages.  This will also be used for creating error messages.
 * @param cmd_mctp_ptr The command interface for legacy processing of MCTP response messages.  This
 * can be null if sending requests is not necessary.
 * @param cmd_spdm_ptr The command interface for legacy processing of SPDM response messages. This
 * is optional and can be set to NULL if SPDM responses are not supported.
 */
#define	mctp_interface_static_init(state_ptr, req_handler_ptr, device_mgr_ptr, channel_ptr, \
	cmd_cerberus_ptr, cmd_mctp_ptr, cmd_spdm_ptr)	{ \
		MCTP_INTERFACE_ISSUE_REQUEST_INIT (channel_ptr, cmd_mctp_ptr, cmd_spdm_ptr) \
		.state = state_ptr, \
		.req_handler = req_handler_ptr, \
		.device_manager = device_mgr_ptr, \
		.cmd_cerberus = cmd_cerberus_ptr, \
	}


#endif /* MCTP_INTERFACE_STATIC_H_ */
