// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MSG_TRANSPORT_H_
#define MSG_TRANSPORT_H_

#include <stdint.h>
#include "cmd_interface.h"
#include "status/rot_status.h"


/**
 * Interface for sending request messages to a remote party and handling the response.
 */
struct msg_transport {
	/**
	 * Get the maximum amount of overhead the transport could add to the message during
	 * transmission.  For transports that will packetize the message, this represents the total
	 * possible overhead added across all packets, not just the header length on a single packet.
	 *
	 * The reported value may change between calls, even for the same destination ID.
	 *
	 * @param transport The message transport to query.
	 * @param dest_id Identifier for the intended recipient of the request.
	 *
	 * @return The maximum number of bytes that can be added to a message or an error code.
	 */
	int (*get_max_message_overhead) (const struct msg_transport *transport, uint8_t dest_id);

	/**
	 * Get the largest payload size supported by the transport for a single message.
	 *
	 * The reported value may change between calls, even for the same destination ID.
	 *
	 * @param transport The message transport to query.
	 * @param dest_id Identifier for the intended recipient of the request.
	 *
	 * @return The maximum message payload supported by the transport or an error code.
	 */
	int (*get_max_message_payload_length) (const struct msg_transport *transport, uint8_t dest_id);

	/**
	 * Get the maximum amount of space needed to hold any fully encapsulated message being sent over
	 * the transport.  This represents the buffer space that should be available to the transport
	 * when sending messages and is the total of the maximum overhead and payload lengths.
	 *
	 * The reported value may change between calls, even for the same destination ID.
	 *
	 * @param transport The message transport to query.
	 * @param dest_id Identifier for the intended recipient of the request.
	 *
	 * @return The maximum number of bytes that could be used to encapsulate a message payload for
	 * transmission.
	 */
	int (*get_max_encapsulated_message_length) (const struct msg_transport *transport,
		uint8_t dest_id);

	/**
	 * Get the amount of overhead the transport would add to a message buffer of a specified size,
	 * assuming the buffer is filled with the maximum amount of payload data that could fit into the
	 * buffer.  For transports that will packetize the message, this represents the total overhead
	 * across all packets, not the just the length on a single packet.
	 *
	 * @param transport The message transport to query.
	 * @param dest_id Identifier for the intended recipient of the request.
	 * @param length The length of the message buffer to use when determining message overhead.
	 *
	 * @return The number of bytes that can be added to the message or an error code.
	 */
	int (*get_buffer_overhead) (const struct msg_transport *transport, uint8_t dest_id,
		size_t length);

	/**
	 * Encapsulate message data for the transport and send the request to a remote receiver.  Wait
	 * for a response to be received for the request.
	 *
	 * @param transport The message transport to use for sending the message.
	 * @param request The request message to send.  The message contents will be modified while
	 * preparing the message to be sent, so there are no guarantees about preserving the contents,
	 * even in error scenarios.  This structure must be initialized using
	 * {@link msg_transport_create_request}.
	 * @param timeout_ms The amount of time, in milliseconds, to wait for a response.  If this is 0,
	 * the call will not wait for a response and any response message that may get received will be
	 * dropped by the transport.
	 * @param response Output for the received response message.  This can be the same message
	 * structure as the request.  If so, the request data will be completely replaced with the
	 * response data.  If this is different from the request message descriptor, it must be
	 * initialized using {@link msg_transport_create_empty_response}.  This can be null if call does
	 * not wait for a response (i.e. timeout is 0).
	 *
	 * @return 0 if the transaction was completed successfully, which means the request was sent and
	 * a response was received, or an error code.  A return of MSG_TRANSPORT_NO_WAIT_RESPONSE means
	 * the request was sent successfully, but the call did not wait for a response.
	 */
	int (*send_request_message) (const struct msg_transport *transport,
		struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response);
};


int msg_transport_create_empty_request (const struct msg_transport *transport, uint8_t *msg_buffer,
	size_t length, uint8_t dest_id, struct cmd_interface_msg *request);
int msg_transport_create_empty_response (uint8_t *msg_buffer, size_t length,
	struct cmd_interface_msg *response);


#define	MSG_TRANSPORT_ERROR(code)		ROT_ERROR (ROT_MODULE_MSG_TRANSPORT, code)

/**
 * Error codes that can be generated by the message transport.
 */
enum {
	MSG_TRANSPORT_INVALID_ARGUMENT = MSG_TRANSPORT_ERROR (0x00),			/**< Input parameter is null or not valid. */
	MSG_TRANSPORT_NO_MEMORY = MSG_TRANSPORT_ERROR (0x01),					/**< Memory allocation failed. */
	MSG_TRANSPORT_MAX_OVERHEAD_FAILED = MSG_TRANSPORT_ERROR (0x02),			/**< Failed to determine the maximum transport overhead. */
	MSG_TRANSPORT_MAX_PAYLOAD_FAILED = MSG_TRANSPORT_ERROR (0x03),			/**< Failed to determine the maximum transport payload. */
	MSG_TRANSPORT_MAX_BUFFER_FAILED = MSG_TRANSPORT_ERROR (0x04),			/**< Failed to determine tha maximum encapsulated length. */
	MSG_TRANSPORT_OVERHEAD_FAILED = MSG_TRANSPORT_ERROR (0x05),				/**< Failed to determine the message overhead size. */
	MSG_TRANSPORT_SEND_REQUEST_FAILED = MSG_TRANSPORT_ERROR (0x06),			/**< Failed to send a request message. */
	MSG_TRANSPORT_REQUEST_TIMEOUT = MSG_TRANSPORT_ERROR (0x07),				/**< Timeout while waiting for a response. */
	MSG_TRANSPORT_NO_WAIT_RESPONSE = MSG_TRANSPORT_ERROR (0x08),			/**< Did not wait for a response after sending a request. */
	MSG_TRANSPORT_OVERHEAD_MORE_THAN_BUFFER = MSG_TRANSPORT_ERROR (0x09),	/**< The request buffer is smaller than the transport overhead. */
	MSG_TRANSPORT_REQUEST_TOO_LARGE = MSG_TRANSPORT_ERROR (0x0a),			/**< The request payload exceeds the transport maximum. */
	MSG_TRANSPORT_RESPONSE_TOO_LARGE = MSG_TRANSPORT_ERROR (0x0b),			/**< The response payload exceeds the provided buffer space. */
	MSG_TRANSPORT_UNEXPECTED_RESPONSE = MSG_TRANSPORT_ERROR (0x0c),			/**< The response does not match the request. */
	MSG_TRANSPORT_RESPONSE_TOO_SHORT = MSG_TRANSPORT_ERROR (0x0d),			/**< A response message does not contain enough data. */
};


#endif	/* MSG_TRANSPORT_H_ */
