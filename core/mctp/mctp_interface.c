// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "mctp_base_protocol.h"
#include "mctp_control_protocol.h"
#include "mctp_control_protocol_commands.h"
#include "mctp_interface.h"
#include "mctp_logging.h"
#include "cmd_interface/cerberus_protocol.h"
#include "common/buffer_util.h"
#include "common/common_math.h"
#include "common/unused.h"
#include "spdm/spdm_protocol.h"


/**
 * Generate a list of MCTP packets that should be transmitted for an MCTP message.  Except for the
 * last packet, all packets in the list will be the same size.
 *
 * @param mctp MCTP handler generating the MCTP packets.
 * @param payload Buffer that contains the MCTP message payload to packetize.
 * @param payload_len Length of message payload.
 * @param dest_eid Destination EID for the MCTP packets.
 * @param dest_addr SMBus address the packets will be sent to.
 * @param src_eid EID of the device sending the packets.
 * @param src_addr SMBus address of the source device.
 * @param msg_tag MCTP message tag to use in the packet header.
 * @param tag_owner MCTP tag owner to use in the packet header.
 * @param packets Output buffer to fill with the list of MCTP packets.
 * @param max_list_len Maximum length of the packet list buffer.
 * @param max_packet_len Output to provide the length of a full MCTP packet.
 *
 * @return Total length of the list of MCTP packets or an error code.
 */
static int mctp_interface_generate_packets_from_payload (const struct mctp_interface *mctp,
	const uint8_t *payload, size_t payload_len, uint8_t dest_eid, uint8_t dest_addr,
	uint8_t src_eid, uint8_t src_addr, uint8_t msg_tag, uint8_t tag_owner, uint8_t *packets,
	size_t max_list_len, size_t *max_packet_len)
{
	uint8_t packet_seq = 0;
	size_t max_packet_payload;
	size_t packet_payload_len;
	size_t i_payload = 0;
	size_t i_packets = 0;
	bool som = true;
	bool eom = false;
	int status;

	max_packet_payload = device_manager_get_max_transmission_unit_by_eid (mctp->device_manager,
		dest_eid);

	while (payload_len > 0) {
		if (payload_len > max_packet_payload) {
			packet_payload_len = max_packet_payload;
		}
		else {
			eom = true;
			packet_payload_len = payload_len;
		}

		status = mctp_base_protocol_construct (&payload[i_payload], packet_payload_len,
			&packets[i_packets], max_list_len - i_packets, src_addr, dest_eid, src_eid, som, eom,
			packet_seq, msg_tag, tag_owner, dest_addr);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		if (som) {
			*max_packet_len = status;
		}

		i_packets += status;
		i_payload += packet_payload_len;
		payload_len -= packet_payload_len;

		som = false;
		packet_seq = (packet_seq + 1) % 4;
	}

	return i_packets;
}

/**
 * Reset MCTP message assembly.  This discards previously received packets and begins looking for a
 * new message.
 *
 * @param mctp The MCTP layer to reset.
 */
static void mctp_interface_reset_message_assembly (const struct mctp_interface *mctp)
{
	mctp->state->req_buffer.data = &mctp->state->msg_buffer[sizeof (mctp->state->msg_buffer) -
			MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	mctp->state->resp_buffer.data = mctp->state->msg_buffer;
	mctp->state->start_packet_len = 0;

	cmd_interface_msg_new_message (&mctp->state->req_buffer, 0, 0, 0, 0);
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
int mctp_interface_get_max_message_overhead (const struct msg_transport *transport, uint8_t dest_id)
{
	const struct mctp_interface *mctp = (const struct mctp_interface*) transport;
	size_t max_message;
	size_t packet_size;
	size_t max_packets;

	if (mctp == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	max_message = device_manager_get_max_message_len_by_eid (mctp->device_manager, dest_id);
	packet_size = device_manager_get_max_transmission_unit_by_eid (mctp->device_manager, dest_id);

	max_packets = MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (max_message, packet_size);

	return MCTP_BASE_PROTOCOL_PACKET_OVERHEAD * max_packets;
}

int mctp_interface_get_max_message_payload_length (const struct msg_transport *transport,
	uint8_t dest_id)
{
	const struct mctp_interface *mctp = (const struct mctp_interface*) transport;

	if (mctp == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	return device_manager_get_max_message_len_by_eid (mctp->device_manager, dest_id);
}

int mctp_interface_get_max_encapsulated_message_length (const struct msg_transport *transport,
	uint8_t dest_id)
{
	const struct mctp_interface *mctp = (const struct mctp_interface*) transport;
	size_t max_message;
	size_t packet_size;
	size_t max_packets;

	if (mctp == NULL) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	max_message = device_manager_get_max_message_len_by_eid (mctp->device_manager, dest_id);
	packet_size = device_manager_get_max_transmission_unit_by_eid (mctp->device_manager, dest_id);

	max_packets = MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (max_message, packet_size);

	return MCTP_BASE_PROTOCOL_MESSAGE_LEN (max_packets, max_message);
}

int mctp_interface_get_buffer_overhead (const struct msg_transport *transport, uint8_t dest_id,
	size_t length)
{
	const struct mctp_interface *mctp = (const struct mctp_interface*) transport;
	size_t packet_size;
	size_t full_packets;
	size_t total_overhead;
	size_t last_remaining;

	packet_size = device_manager_get_max_transmission_unit_by_eid (mctp->device_manager, dest_id);
	packet_size += MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	full_packets = length / packet_size;
	total_overhead = full_packets * MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;

	/* Add overhead for the last possible packet in the buffer, which may not even have enough room
	 * for the MCTP packet header. */
	last_remaining = length % packet_size;
	if (last_remaining < MCTP_BASE_PROTOCOL_PACKET_OVERHEAD) {
		total_overhead += last_remaining;
	}
	else {
		total_overhead += MCTP_BASE_PROTOCOL_PACKET_OVERHEAD;
	}

	return total_overhead;
}

/**
 * @deprecated Pairs with the deprecated issue_request call and will be removed.
 *
 * Handle a response message for a request issued with issue_request.
 *
 * @param mctp The MCTP handler that has received a response message.
 *
 * @return 0 if response processing was successful or an error code.
 */
static int mctp_interface_deprecated_handle_response_message (const struct mctp_interface *mctp)
{
	int status;

	/* We know the message is one of the three supported types by this point.  If it wasn't,
	 * it would have failed earlier in packet processing. */
	if (MCTP_BASE_PROTOCOL_IS_CONTROL_MSG (mctp->state->msg_type)) {
		if (mctp->cmd_mctp) {
			status = mctp->cmd_mctp->process_response (mctp->cmd_mctp, &mctp->state->req_buffer);
			if (status == CMD_HANDLER_ERROR_MESSAGE) {
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_MCTP_CONTROL_RSP_FAIL, status, mctp->state->channel_id);
			}
		}
		else {
			status = MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION;
			goto exit;
		}
	}
	else if (MCTP_BASE_PROTOCOL_IS_VENDOR_MSG (mctp->state->msg_type)) {
		status = mctp->cmd_cerberus->process_response (mctp->cmd_cerberus,
			&mctp->state->req_buffer);
	}
	else if (MCTP_BASE_PROTOCOL_IS_SPDM_MSG (mctp->state->msg_type)) {
		if (mctp->cmd_spdm) {
			cmd_interface_msg_remove_protocol_header (&mctp->state->req_buffer,
				sizeof (struct spdm_protocol_mctp_header));

			status = mctp->cmd_spdm->process_response (mctp->cmd_spdm, &mctp->state->req_buffer);
		}
		else {
			status = MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION;
			goto exit;
		}
	}
	else {
		status = MCTP_BASE_PROTOCOL_UNSUPPORTED_OPERATION;
	}

	if (status == CMD_HANDLER_ERROR_MESSAGE) {
		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_ERROR_DEPRECATED;
		status = 0;
	}
	else if (status != 0) {
		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_FAIL_DEPRECATED;
	}
	else {
		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_SUCCESS;
	}

	platform_semaphore_post (&mctp->state->wait_for_response);

exit:
	mctp_interface_reset_message_assembly (mctp);
	platform_mutex_unlock (&mctp->state->response_lock);

	return status;
}

int mctp_interface_send_request_message (const struct msg_transport *transport,
	struct cmd_interface_msg *request, uint32_t timeout_ms, struct cmd_interface_msg *response)
{
	const struct mctp_interface *mctp = (const struct mctp_interface*) transport;
	struct mctp_base_protocol_message_header *msg_header;
	struct cmd_message cmd_msg;
	uint8_t msg_type;
	int src_eid;
	int src_addr;
	int dest_eid;
	int dest_addr;
	int status;

	if ((mctp == NULL) || (request == NULL)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	/* A response descriptor is only required if the caller wants the response message. */
	if ((response == NULL) && (timeout_ms != 0)) {
		return MSG_TRANSPORT_INVALID_ARGUMENT;
	}

	dest_eid = request->target_eid;
	dest_addr = device_manager_get_device_addr_by_eid (mctp->device_manager, request->target_eid);
	if (ROT_IS_ERROR (dest_addr)) {
		return dest_addr;
	}

	if (request->payload_length >
		device_manager_get_max_message_len_by_eid (mctp->device_manager, request->target_eid)) {
		return MSG_TRANSPORT_REQUEST_TOO_LARGE;
	}

	msg_header = (struct mctp_base_protocol_message_header*) request->payload;
	msg_type = msg_header->msg_type;

	src_eid = device_manager_get_device_eid (mctp->device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM);
	src_addr = device_manager_get_device_addr (mctp->device_manager,
		DEVICE_MANAGER_SELF_DEVICE_NUM);

	/* The transport needs to be locked before building the message since it uses the next response
	 * tag as part of the packet construction. */
	platform_mutex_lock (&mctp->state->request_lock);

	status = mctp_interface_generate_packets_from_payload (mctp, request->payload,
		request->payload_length, request->target_eid, dest_addr, src_eid, src_addr,
		mctp->state->next_msg_tag, MCTP_BASE_PROTOCOL_TO_REQUEST, request->data,
		request->max_response, &cmd_msg.pkt_size);
	if (ROT_IS_ERROR (status)) {
		goto unlock_tx;
	}

	cmd_msg.msg_size = status;
	cmd_msg.data = request->data;
	cmd_msg.dest_addr = dest_addr;

	/* Do not manipulate any of the response handling state if the handler is currently processing
	 * a received response message. */
	platform_mutex_lock (&mctp->state->response_lock);

	if (timeout_ms != 0) {
		status = platform_semaphore_reset (&mctp->state->wait_for_response);
		if (status != 0) {
			platform_mutex_unlock (&mctp->state->response_lock);
			goto unlock_tx;
		}

		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_WAITING;
	}
	else {
		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_PENDING;
	}

	mctp->state->response_msg_tag = mctp->state->next_msg_tag;
	mctp->state->response_msg_type = msg_type;
	mctp->state->response_msg = response;

	/* The message tag has been consumed, regardless of whether the message transaction is
	 * successful, so increment it for the next message. */
	mctp->state->next_msg_tag = (mctp->state->next_msg_tag + 1) % 8;
	platform_mutex_unlock (&mctp->state->response_lock);

	status = cmd_channel_send_message (mctp->channel, &cmd_msg);
	if (status != 0) {
		/* Reset to the idle state since request transmission failed. */
		platform_mutex_lock (&mctp->state->response_lock);
		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_IDLE;
		platform_mutex_unlock (&mctp->state->response_lock);

		goto unlock_tx;
	}

	if (timeout_ms == 0) {
		status = MSG_TRANSPORT_NO_WAIT_RESPONSE;
		goto unlock_tx;
	}

	status = platform_semaphore_wait (&mctp->state->wait_for_response, timeout_ms);

	/* Take the response handling lock again to clear up the response state, particularly to handle
	 * error cases. */
	platform_mutex_lock (&mctp->state->response_lock);

	if (status == 0) {
		if (mctp->state->rsp_state == MCTP_INTERFACE_RESPONSE_TOO_BIG) {
			status = MSG_TRANSPORT_RESPONSE_TOO_LARGE;
		}
	}
	else if (status == 1) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_RSP_TIMEOUT, (dest_eid << 8) | mctp->state->response_msg_tag, timeout_ms);

		status = MSG_TRANSPORT_REQUEST_TIMEOUT;
	}

	mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_IDLE;
	platform_mutex_unlock (&mctp->state->response_lock);

unlock_tx:
	mctp->state->response_msg = NULL;
	platform_mutex_unlock (&mctp->state->request_lock);

	return status;
}
#endif

/**
 * Check a response packet against the MCTP transport state to see if it's part of an expected
 * response message.
 *
 * @param mctp The MCTP handler to check the packet against.
 * @param msg_tag Message tag of the response packet.
 * @param som Flag indicating if the packet is the first in the message.
 * @param msg_type Message type of the response message.  This is only valid for SOM packets.
 *
 * @return true if the response message is part of an expected response or false if not.
 */
static bool mctp_interface_is_expected_response (const struct mctp_interface *mctp, uint8_t msg_tag,
	bool som, uint8_t msg_type)
{
#ifdef CMD_ENABLE_ISSUE_REQUEST
	bool expected = true;

	platform_mutex_lock (&mctp->state->response_lock);

	if ((mctp->state->rsp_state != MCTP_INTERFACE_RESPONSE_WAITING) &&
		(mctp->state->rsp_state != MCTP_INTERFACE_RESPONSE_PENDING) &&
		(mctp->state->rsp_state != MCTP_INTERFACE_RESPONSE_WAITING_DEPRECATED)) {
		/* We are not waiting for any response.  Just drop the message. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_RSP_DROPPED, MCTP_LOGGING_RSP_DROPPED_UNEXPECTED, mctp->state->channel_id);

		expected = false;
		goto exit;
	}

	if (msg_tag != mctp->state->response_msg_tag) {
		/* This response message does not match the request that was sent.  Drop it. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_RSP_DROPPED, MCTP_LOGGING_RSP_DROPPED_WRONG_TAG,
			(mctp->state->response_msg_tag << 16) | (msg_tag << 8) |
				mctp->state->channel_id);

		expected = false;
		goto exit;
	}

	if (som && (msg_type != mctp->state->response_msg_type)) {
		/* MCTP message assembly should not be interrupted by packets for an unsupported message
		 * type.  The message type is only present in the SOM packet.  For response messages, assume
		 * the message type should match the request message that was sent. Drop it. */
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_RSP_DROPPED, MCTP_LOGGING_RSP_DROPPED_WRONG_TYPE,
			(mctp->state->response_msg_type << 16) | (msg_type << 8) |
				mctp->state->channel_id);

		expected = false;
	}

exit:
	platform_mutex_unlock (&mctp->state->response_lock);

	return expected;
#else
	UNUSED (msg_tag);
	UNUSED (som);
	UNUSED (msg_type);

	/* Always drop response messages if issuing requests is not supported. */
	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MCTP,
		MCTP_LOGGING_RSP_DROPPED, MCTP_LOGGING_RSP_DROPPED_UNEXPECTED, mctp->state->channel_id);

	return false;
#endif
}

/**
 * Handle a received response message to pair it with any outstanding request.
 *
 * @param mctp The MCTP handler that has received a response message.
 *
 * @return 0 or the result of any deprecated response processing.
 */
static int mctp_interface_handle_response_message (const struct mctp_interface *mctp)
{
#ifdef CMD_ENABLE_ISSUE_REQUEST
	platform_mutex_lock (&mctp->state->response_lock);

	/* Handle deprecated response processing. */
	if (mctp->state->rsp_state == MCTP_INTERFACE_RESPONSE_WAITING_DEPRECATED) {
		return mctp_interface_deprecated_handle_response_message (mctp);
	}

	if (mctp->state->rsp_state == MCTP_INTERFACE_RESPONSE_PENDING) {
		/* Received the expected response message.  Nothing is waiting for it so drop it. */
		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_IDLE;
		mctp_interface_reset_message_assembly (mctp);
		platform_mutex_unlock (&mctp->state->response_lock);

		return 0;
	}

	/* A response was received for the request that was sent.  Copy the response message into the
	 * response buffer. */
	if (mctp->state->req_buffer.length <= mctp->state->response_msg->max_response) {
		cmd_interface_msg_new_message (mctp->state->response_msg,
			mctp->state->req_buffer.source_eid, mctp->state->req_buffer.source_addr,
			mctp->state->req_buffer.target_eid, mctp->state->req_buffer.channel_id);

		cmd_interface_msg_add_payload_data (mctp->state->response_msg, mctp->state->req_buffer.data,
			mctp->state->req_buffer.length);

		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_SUCCESS;
	}
	else {
		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_TOO_BIG;
	}

	mctp_interface_reset_message_assembly (mctp);
	platform_semaphore_post (&mctp->state->wait_for_response);
	platform_mutex_unlock (&mctp->state->response_lock);

	return 0;
#else
	UNUSED (mctp);

	return 0;
#endif
}

/**
 * Handle a received request message to generate an appropriate response.
 *
 * @param mctp The MCTP handler that received the message.
 * @param rx_packet The last received packet in the message.
 * @param tx_message Output for a response message to send.  If this is null, there is was no
 * response generated for the received data.  If this is not null, this will point to the packetized
 * message data in the MCTP message buffer.
 *
 * @return 0 if the request was processed successfully or an error code.
 */
static int mctp_interface_handle_request_message (const struct mctp_interface *mctp,
	struct cmd_packet *rx_packet, struct cmd_message **tx_message)
{
	uint8_t response_addr;
	int status;

	mctp->state->req_buffer.max_response = MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY;

	status = mctp->req_handler->base.process_request (&mctp->req_handler->base,
		&mctp->state->req_buffer);
	if (status != 0) {
		mctp_interface_reset_message_assembly (mctp);

		return status;
	}

	/* Check to see if the response requires the message timeout to be adjusted. */
	if (rx_packet->timeout_valid && mctp->state->req_buffer.crypto_timeout) {
		platform_increase_timeout (MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS -
			MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS,	&rx_packet->pkt_timeout);
	}

	/* If a response was generated during request processing, packetize the message for transmission
	 * back to the requester. */
	if (mctp->state->req_buffer.length > 0) {
		response_addr = mctp->state->req_buffer.source_addr;

		status = mctp_interface_generate_packets_from_payload (mctp, mctp->state->req_buffer.data,
			mctp->state->req_buffer.length, mctp->state->req_buffer.source_eid, response_addr,
			mctp->state->req_buffer.target_eid, rx_packet->dest_addr, mctp->state->msg_tag,
			MCTP_BASE_PROTOCOL_TO_RESPONSE, mctp->state->resp_buffer.data,
			sizeof (mctp->state->msg_buffer), &mctp->state->resp_buffer.pkt_size);

		mctp_interface_reset_message_assembly (mctp);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		mctp->state->resp_buffer.msg_size = status;
		mctp->state->resp_buffer.dest_addr = response_addr;

		*tx_message = &mctp->state->resp_buffer;
	}
	else {
		mctp_interface_reset_message_assembly (mctp);
		*tx_message = NULL;
	}

	return 0;
}

/**
 * Initialize a handler for MCTP messages.  MCTP packets will use the SMBus transport binding.
 *
 * @param mctp The MCTP interface to initialize.
 * @param state Variable context for the MCTP message handler.  This must be uninitialized.
 * @param req_handler The handler to call processing a received MCTP request message.  This handler
 * will be called irrespective of the message type.
 * @param device_mgr The device manager linked to command interface.
 * @param channel The channel to use for sending request messages.  This can be null if sending
 * requests is not necessary.
 * @param cmd_cerberus The command interface for legacy processing of Cerberus response messages.
 * This can be null if sending requests is not necessary.
 * @param cmd_mctp The command interface for legacy processing of MCTP response messages.  This can
 * be null if sending requests is not necessary.
 * @param cmd_spdm The command interface for legacy processing of SPDM response messages. This is
 * optional and can be set to NULL if SPDM responses are not supported.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int mctp_interface_init (struct mctp_interface *mctp, struct mctp_interface_state *state,
	const struct cmd_interface_multi_handler *req_handler, struct device_manager *device_mgr,
	const struct cmd_channel *channel, const struct cmd_interface *cmd_cerberus,
	const struct cmd_interface *cmd_mctp, const struct cmd_interface *cmd_spdm)
{
	if (mctp == NULL) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	memset (mctp, 0, sizeof (struct mctp_interface));

#ifdef CMD_ENABLE_ISSUE_REQUEST
	mctp->base.get_max_message_overhead = mctp_interface_get_max_message_overhead;
	mctp->base.get_max_message_payload_length = mctp_interface_get_max_message_payload_length;
	mctp->base.get_max_encapsulated_message_length =
		mctp_interface_get_max_encapsulated_message_length;
	mctp->base.get_buffer_overhead = mctp_interface_get_buffer_overhead;
	mctp->base.send_request_message = mctp_interface_send_request_message;

	mctp->channel = channel;
	mctp->cmd_cerberus = cmd_cerberus;
	mctp->cmd_mctp = cmd_mctp;
	mctp->cmd_spdm = cmd_spdm;
#else
	UNUSED (channel);
	UNUSED (cmd_cerberus);
	UNUSED (cmd_mctp);
	UNUSED (cmd_spdm);
#endif

	mctp->state = state;
	mctp->req_handler = req_handler;
	mctp->device_manager = device_mgr;

	return mctp_interface_init_state (mctp);
}

/**
 * Initialize only the variable state for an MCTP message handler.  The rest of the MCTP instance is
 * assumed to have already been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param mctp The MCTP handler instance that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int mctp_interface_init_state (const struct mctp_interface *mctp)
{
#ifdef CMD_ENABLE_ISSUE_REQUEST
	int status;
#endif

	if ((mctp == NULL) || (mctp->state == NULL) || (mctp->req_handler == NULL) ||
		(mctp->device_manager == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	memset (mctp->state, 0, sizeof (struct mctp_interface_state));

#ifdef CMD_ENABLE_ISSUE_REQUEST
	status = platform_semaphore_init (&mctp->state->wait_for_response);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&mctp->state->request_lock);
	if (status != 0) {
		goto free_rx_wait;
	}

	status = platform_mutex_init (&mctp->state->response_lock);
	if (status != 0) {
		goto free_tx_lock;
	}
#endif

	mctp_interface_reset_message_assembly (mctp);

	return 0;

#ifdef CMD_ENABLE_ISSUE_REQUEST
free_tx_lock:
	platform_mutex_free (&mctp->state->request_lock);
free_rx_wait:
	platform_semaphore_free (&mctp->state->wait_for_response);

	return status;
#endif
}

/**
 * Release the resources used by an SMBus MCTP handler.
 *
 * @param mctp The MCTP handler to release.
 */
void mctp_interface_release (const struct mctp_interface *mctp)
{
#ifdef CMD_ENABLE_ISSUE_REQUEST
	if (mctp != NULL) {
		platform_semaphore_free (&mctp->state->wait_for_response);
		platform_mutex_free (&mctp->state->request_lock);
		platform_mutex_free (&mctp->state->response_lock);
	}
#else
	UNUSED (mctp);
#endif
}

/**
 * Assign a channel identifier to the MCTP handler.
 *
 * @param mctp The MCTP interface to assign the channel ID.
 * @param channel_id The channel ID to associate with this interface.
 *
 * @return 0 if the channel ID was successfully assigned or an error code.
 */
int mctp_interface_set_channel_id (const struct mctp_interface *mctp, int channel_id)
{
	if (mctp == NULL) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	mctp->state->channel_id = channel_id;

	return 0;
}

/**
 * Drop an invalid or unsupported MCTP packet.
 *
 * @param mctp The MCTP transport layer that received the packet.
 * @param rx_packet The packet being dropped.
 * @param error_data Detailed information about the error cause.
 * @param src_eid EID for the packet sender.
 * @param dest_eid EID for the packet target.
 * @param msg_tag Message tag for the message containing the invalid packet.
 * @param alt_data Alternative error data for logging.
 *
 * @return Always returns 0.  No error needs to be reported, since the condition has been logged
 * here.
 */
static int mctp_interface_drop_packet (const struct mctp_interface *mctp,
	const struct cmd_packet *rx_packet, uint32_t error_data, uint8_t src_eid, uint8_t dest_eid,
	uint8_t msg_tag, uint32_t alt_data)
{
	uint32_t msg1 = 0;
	uint32_t msg2 = 0;
	uint8_t byte;

	/* When MCTP packets get dropped, they are silently discarded.  There is no active NACK or other
	 * error reporting in the MCTP spec.  Log the packet information for debugging and telemetry
	 * purposes. */
	msg2 = rx_packet->pkt_size << 24;
	for (byte = 0; byte < 7; ++byte) {
		if (byte < 4) {
			msg1 |= (rx_packet->data[byte] << (byte * 8));
		}
		else {
			msg2 |= (rx_packet->data[byte] << ((byte - 4) * 8));
		}
	}

	debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MCTP, MCTP_LOGGING_CHANNEL,
		mctp->state->channel_id, 0);
	debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
		MCTP_LOGGING_PKT_DROPPED, msg1, msg2);

	if (error_data != MCTP_BASE_PROTOCOL_PKT_TOO_SHORT) {
		switch (error_data) {
			case MCTP_BASE_PROTOCOL_BAD_CHECKSUM:
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_PROTOCOL_ERROR,
					(((uint32_t) CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM << 24) | (src_eid << 16) |
								(dest_eid << 8) | msg_tag),	alt_data);
				break;

			case MCTP_BASE_PROTOCOL_NO_SOM:
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_PROTOCOL_ERROR,
					(((uint32_t) CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG << 24) | (src_eid << 16) |
								(dest_eid << 8) | msg_tag),	0);
				break;

			case MCTP_BASE_PROTOCOL_OUT_OF_SEQUENCE:
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_PROTOCOL_ERROR,
					(((uint32_t) CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW << 24) |
								(src_eid << 16) | (dest_eid << 8) | msg_tag), 0);
				break;

			case MCTP_BASE_PROTOCOL_MIDDLE_PKT_LENGTH:
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_PROTOCOL_ERROR,
					(((uint32_t) CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN << 24) |
								(src_eid << 16) | (dest_eid << 8) | msg_tag), alt_data);
				break;

			case MCTP_BASE_PROTOCOL_MSG_TOO_LARGE:
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_PROTOCOL_ERROR,
					(((uint32_t) CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW << 24) | (src_eid << 16) |
								(dest_eid << 8) | msg_tag),	alt_data);

				break;

			default:
				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_PROTOCOL_ERROR,
					(((uint32_t) CERBERUS_PROTOCOL_ERROR_INVALID_REQ << 24) | (src_eid << 16) |
								(dest_eid << 8) | msg_tag),	error_data);
				break;
		}
	}

	return 0;
}

/**
 * Process a received MCTP packet using the SMBus transport binding.
 *
 * If the packet completes an MCTP message, the request handler will get called to process the
 * message and generate an appropriate response.  If the packet only represents a partial message,
 * the data will be saved until the rest of the message has been received.
 *
 * @param mctp The MCTP handler that will process the packet.
 * @param rx_packet The received packet to process.  Upon return, it is always safe for the caller
 * to reuse this packet context for new data.
 * @param tx_message Output for a response message to send.  If this is null, there is was no
 * response generated for the received data.  If this is not null, it represents a packetized MCTP
 * message that should be transmitted.  This pointer MUST NOT be freed by the caller and is only
 * valid until the next call to {@link mctp_interface_process_packet}.
 *
 * @return Completion status, 0 if success or an error code.
 */
int mctp_interface_process_packet (const struct mctp_interface *mctp, struct cmd_packet *rx_packet,
	struct cmd_message **tx_message)
{
	const uint8_t *payload;
	uint8_t src_eid = 0;
	uint8_t dest_eid = 0;
	uint8_t msg_tag = 0;
	uint8_t packet_seq;
	uint8_t crc = 0;
	uint8_t response_addr = 0;
	uint8_t tag_owner;
	uint8_t msg_type;
	size_t payload_len;
	bool som;
	bool eom;
	int self_eid;
	int status;

	if ((mctp == NULL) || (rx_packet == NULL) || (tx_message == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	*tx_message = NULL;

	self_eid = device_manager_get_device_eid (mctp->device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM);
	if (ROT_IS_ERROR (self_eid)) {
		return self_eid;
	}

	/* Parse the received packet. */
	status = mctp_base_protocol_interpret (rx_packet->data, rx_packet->pkt_size,
		rx_packet->dest_addr, &response_addr, &som, &eom, &src_eid, &dest_eid, &payload,
		&payload_len, &msg_tag, &packet_seq, &crc, &msg_type, &tag_owner);
	if (status == 0) {
		/* If the packet is not destined for this device, ignore it. */
		if ((dest_eid != self_eid) && (dest_eid != MCTP_BASE_PROTOCOL_NULL_EID)) {
			return 0;
		}

		if (tag_owner == MCTP_BASE_PROTOCOL_TO_RESPONSE) {
			if (!mctp_interface_is_expected_response (mctp, msg_tag, som, msg_type)) {
				/* Unexpected response packets must not interrupt message assembly and should be
				 * ignored. */
				return 0;
			}
		}
		else if (som) {
			/* MCTP message assembly should not be interrupted by packets for an unsupported message
			 * type.  The message type is only present in the SOM packet.  For request messages,
			 * check the request handler to see if the message type is supported. */
			status = mctp->req_handler->is_message_type_supported (mctp->req_handler, msg_type);
			if (status == CMD_HANDLER_UNKNOWN_MESSAGE_TYPE) {
				status = MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG;
			}
		}
	}

	if (status != 0) {
		/* Drop the packet if it's invalid in some way.  This must not impact any active message
		 * assembly. */
		return mctp_interface_drop_packet (mctp, rx_packet, status, src_eid, dest_eid, msg_tag,
			crc);
	}

	/* Check message assembly state relative to the new packet that was received. */
	if (som) {
		if (mctp->state->start_packet_len != 0) {
			/* A new message is being started before the previous one has completed.  This is
			 * considered an error scenario by MCTP, so it's logged. */
			debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MCTP,
				MCTP_LOGGING_CHANNEL, mctp->state->channel_id, 0);
			debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
				MCTP_LOGGING_RESTART_MESSAGE,
				((mctp->state->req_buffer.source_eid << 24) | (mctp->state->msg_tag << 16) |
							(mctp->state->tag_owner << 8) | mctp->state->msg_type),
				((src_eid << 24) | (msg_tag << 16) | (tag_owner << 8) | msg_type));
		}

		cmd_interface_msg_new_message (&mctp->state->req_buffer, src_eid, response_addr, dest_eid,
			mctp->state->channel_id);

		mctp->state->start_packet_len = payload_len;
		mctp->state->packet_seq = packet_seq;
		mctp->state->msg_tag = msg_tag;
		mctp->state->msg_type = msg_type;
		mctp->state->tag_owner = tag_owner;
	}
	else if (mctp->state->start_packet_len == 0) {
		/* Drop the packet if this packet is not a SOM and there is no message currently being
		 * assembled. */
		return mctp_interface_drop_packet (mctp, rx_packet, MCTP_BASE_PROTOCOL_NO_SOM, src_eid,
			dest_eid, msg_tag, 0);
	}
	else if ((msg_tag != mctp->state->msg_tag) || (tag_owner != mctp->state->tag_owner)) {
		/* This is a special case of the no SOM handling.  In this case, a packet was received for a
		 * message terminus that is different from the message currently being assembled.
		 *
		 * Drop the packet and do not interrupt message assembly. */
		return mctp_interface_drop_packet (mctp, rx_packet, MCTP_BASE_PROTOCOL_UNEXPECTED_PKT,
			src_eid, dest_eid, msg_tag, 0);
	}
	else if (src_eid != mctp->state->req_buffer.source_eid) {
		/* This is the same special case for no SOM handling, but in this case the message terminus
		 * is different because of the source EID.  This is handled separately only so that a
		 * different error can be logged.
		 *
		 * Drop the packet and do not interrupt message assembly. */
		return mctp_interface_drop_packet (mctp, rx_packet, MCTP_BASE_PROTOCOL_INVALID_EID,	src_eid,
			dest_eid, msg_tag, 0);
	}
	else if (packet_seq != mctp->state->packet_seq) {
		/* The packet sequence number is wrong.  Reset message assembly and drop the packet. */
		mctp_interface_reset_message_assembly (mctp);

		return mctp_interface_drop_packet (mctp, rx_packet, MCTP_BASE_PROTOCOL_OUT_OF_SEQUENCE,
			src_eid, dest_eid, msg_tag, 0);
	}
	else if ((payload_len != mctp->state->start_packet_len) &&
		!(eom && (payload_len < mctp->state->start_packet_len))) {
		/* Middle packets must be the same size as the first packet.  Reset message assembly and
		 * drop the packet.
		 *
		 * Last packets can be smaller, but not larger, than the first packet. */
		mctp_interface_reset_message_assembly (mctp);

		return mctp_interface_drop_packet (mctp, rx_packet, MCTP_BASE_PROTOCOL_MIDDLE_PKT_LENGTH,
			src_eid, dest_eid, msg_tag, payload_len);
	}

	/* Add the new packet data to the message being assembled. */
	if ((payload_len + mctp->state->req_buffer.length) > MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY) {
		/* The request has grown too large for the message buffer.  Reset message assembly and
		 * drop the packet. */
		payload_len += mctp->state->req_buffer.length;
		mctp_interface_reset_message_assembly (mctp);

		return mctp_interface_drop_packet (mctp, rx_packet, MCTP_BASE_PROTOCOL_MSG_TOO_LARGE,
			src_eid, dest_eid, msg_tag, payload_len);
	}

	cmd_interface_msg_add_payload_data (&mctp->state->req_buffer, payload, payload_len);
	mctp->state->packet_seq = (mctp->state->packet_seq + 1) % 4;

	/* If this is the last packet in the message, process the complete message. */
	if (eom) {
		if (tag_owner == MCTP_BASE_PROTOCOL_TO_RESPONSE) {
			/* The message contains response data. */
			return mctp_interface_handle_response_message (mctp);
		}
		else {
			/* The message contains request data. */
			return mctp_interface_handle_request_message (mctp, rx_packet, tx_message);
		}
	}

	return 0;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
/**
 * @deprecated Do not use this API for new workflows.  Use the msg_transport interface instead.
 * This is only being maintained to support existing workflows temporarily while they get migrated.
 * Once they get moved, this API will be removed.
 *
 * Packetize a request message and send it over a command channel.  This call will block until the
 * full message has been transmitted and a response has been received or the operation times out.
 * If a timeout_ms of 0 is provided, the request is sent and the function returns immediately
 * without waiting for a response.
 *
 * @param mctp MCTP instance that will be processing the request message.
 * @param channel Command channel to use for transmitting the packets.
 * @param dest_addr The destination address for the request.
 * @param dest_eid The destination EID for the request.
 * @param request Buffer that contains the request body to send.
 * @param length Length of the request message before any packetization.
 * @param msg_buffer Buffer that will be used to store the packetized message.  This can be
 * overlapping with the request buffer.  If the buffers overlap, the request data will be modified
 * upon return.
 * @param max_length Maximum length of the message buffer.  This buffer should be
 * MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN bytes to ensure any message packetized in any way can fit.
 * @param timeout_ms Timeout period in milliseconds to wait for response to be received.  If
 * wait for response not needed, set to 0.
 *
 * @return 0 if the request was transmitted successfully or an error code.
 */
int mctp_interface_issue_request (const struct mctp_interface *mctp,
	const struct cmd_channel *channel, uint8_t dest_addr, uint8_t dest_eid, uint8_t *request,
	size_t length, uint8_t *msg_buffer, size_t max_length, uint32_t timeout_ms)
{
	/* TODO: Delete this function in favor of using the msg_transport interface. */
	struct mctp_base_protocol_message_header *msg_header;
	struct cmd_message cmd_msg;
	size_t max_transmission_unit;
	size_t num_packets;
	uint8_t msg_type;
	int src_eid;
	int src_addr;
	int status;

	if ((mctp == NULL) || (channel == NULL) || (request == NULL) || (msg_buffer == NULL) ||
		(length == 0)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	if (length > device_manager_get_max_message_len_by_eid (mctp->device_manager, dest_eid)) {
		return MCTP_BASE_PROTOCOL_MSG_TOO_LARGE;
	}

	max_transmission_unit = device_manager_get_max_transmission_unit_by_eid (mctp->device_manager,
		dest_eid);

	num_packets = (MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (length, max_transmission_unit));

	if (max_length < MCTP_BASE_PROTOCOL_MESSAGE_LEN (num_packets, length)) {
		return MCTP_BASE_PROTOCOL_BUF_TOO_SMALL;
	}

	src_eid = device_manager_get_device_eid (mctp->device_manager, DEVICE_MANAGER_SELF_DEVICE_NUM);
	if (ROT_IS_ERROR (src_eid)) {
		return src_eid;
	}

	src_addr = device_manager_get_device_addr (mctp->device_manager,
		DEVICE_MANAGER_SELF_DEVICE_NUM);
	if (ROT_IS_ERROR (src_addr)) {
		return src_addr;
	}

	if (buffer_are_overlapping (request, length, msg_buffer, max_length)) {
		if ((request + length) != (msg_buffer + max_length)) {
			memmove (msg_buffer + max_length - length, request, length);
			request = msg_buffer + max_length - length;
		}
	}

	msg_header = (struct mctp_base_protocol_message_header*) request;
	msg_type = msg_header->msg_type;

	platform_mutex_lock (&mctp->state->request_lock);

	status = mctp_interface_generate_packets_from_payload (mctp, request, length, dest_eid,
		dest_addr, src_eid, src_addr, mctp->state->next_msg_tag, MCTP_BASE_PROTOCOL_TO_REQUEST,
		msg_buffer, max_length, &cmd_msg.pkt_size);
	if (ROT_IS_ERROR (status)) {
		goto unlock;
	}

	cmd_msg.msg_size = status;
	cmd_msg.data = msg_buffer;
	cmd_msg.dest_addr = dest_addr;

	platform_mutex_lock (&mctp->state->response_lock);

	mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_WAITING_DEPRECATED;
	mctp->state->response_msg_tag = mctp->state->next_msg_tag;
	mctp->state->response_msg_type = msg_type;
	mctp->state->response_msg = NULL;

	mctp->state->next_msg_tag = (mctp->state->next_msg_tag + 1) % 8;

	status = platform_semaphore_reset (&mctp->state->wait_for_response);
	if (status != 0) {
		goto exit;
	}

	platform_mutex_unlock (&mctp->state->response_lock);

	status = cmd_channel_send_message (channel, &cmd_msg);
	if (status != 0) {
		platform_mutex_lock (&mctp->state->response_lock);
		mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_IDLE;
		platform_mutex_unlock (&mctp->state->response_lock);

		goto unlock;
	}

	if (timeout_ms == 0) {
		goto unlock;
	}

	status = platform_semaphore_wait (&mctp->state->wait_for_response, timeout_ms);

	platform_mutex_lock (&mctp->state->response_lock);

	if (status == 1) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_RSP_TIMEOUT, (dest_eid << 8) | mctp->state->response_msg_tag, timeout_ms);

		status = MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT;
	}
	else if (mctp->state->rsp_state == MCTP_INTERFACE_RESPONSE_ERROR_DEPRECATED) {
		status = MCTP_BASE_PROTOCOL_ERROR_RESPONSE;
	}
	else if (mctp->state->rsp_state == MCTP_INTERFACE_RESPONSE_FAIL_DEPRECATED) {
		status = MCTP_BASE_PROTOCOL_FAIL_RESPONSE;
	}

exit:
	mctp->state->rsp_state = MCTP_INTERFACE_RESPONSE_IDLE;
	platform_mutex_unlock (&mctp->state->response_lock);

unlock:
	platform_mutex_unlock (&mctp->state->request_lock);

	return status;
}

/**
 * Generate and send an MCTP control protocol Discovery Notify request to the MCTP bridge.
 *
 * @param mctp MCTP instance that will be processing the request message.
 * @param use_bridge_eid Flag indicating that the request should be sent to the MCTP bridge EID.  If
 * this is false, the request will be sent to the NULL EID.
 * @param timeout_ms The amount of time, in milliseconds, to wait for a response from the bridge.
 * If this is 0, the response will be ignored and the function will return immediately after sending
 * the request.
 * @param response Output for the discovery response message, if one is required.  This must be
 * provided if there is a non-zero timeout.  Otherwise, it can be null.  If provided, it must be
 * initialized per the same parameter in {@link msg_transport.send_request_message}.
 *
 * @return 0 if the request was transmitted successfully or an error code.
 */
int mctp_interface_send_discovery_notify (const struct mctp_interface *mctp, bool use_bridge_eid,
	uint32_t timeout_ms, struct cmd_interface_msg *response)
{
	uint8_t request_data[MCTP_BASE_PROTOCOL_MIN_MESSAGE_LEN];
	struct cmd_interface_msg request;
	int bridge_eid = MCTP_BASE_PROTOCOL_NULL_EID;
	int status;

	if (mctp == NULL) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	if (use_bridge_eid) {
		bridge_eid = device_manager_get_device_eid (mctp->device_manager,
			DEVICE_MANAGER_MCTP_BRIDGE_DEVICE_NUM);
		if (ROT_IS_ERROR (bridge_eid)) {
			return bridge_eid;
		}
	}

	msg_transport_create_empty_request (&mctp->base, request_data, sizeof (request_data),
		bridge_eid, &request);

	cmd_interface_msg_set_message_payload_length (&request,
		mctp_control_protocol_generate_discovery_notify_request (request.payload,
		request.payload_length));

	status = mctp_interface_send_request_message (&mctp->base, &request, timeout_ms, response);
	if (status == MSG_TRANSPORT_NO_WAIT_RESPONSE) {
		status = 0;
	}

	return status;
}

#endif
