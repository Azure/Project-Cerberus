// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "common/common_math.h"
#include "common/buffer_util.h"
#include "cmd_interface/cerberus_protocol.h"
#include "cmd_interface/cmd_interface.h"
#include "cmd_interface/cmd_channel.h"
#include "mctp_control_protocol.h"
#include "mctp_logging.h"
#include "mctp_base_protocol.h"
#include "mctp_interface.h"


/**
 * MCTP interface initialization
 *
 * @param mctp The MCTP interface to initialize.
 * @param cmd_cerberus The command interface to use for processing and generating Cerberus protocol
 * 	messages.
 * @param cmd_mctp The command interface to use for processing and generating MCTP protocol message.
 * @param device_mgr The device manager linked to command interface.
 *
 * @return Initialization status, 0 if success or an error code.
 */
int mctp_interface_init (struct mctp_interface *mctp, struct cmd_interface *cmd_cerberus,
	struct cmd_interface *cmd_mctp, struct device_manager *device_mgr)
{
#ifdef CMD_ENABLE_ISSUE_REQUEST
	int status;
#endif

	if ((mctp == NULL) || (cmd_cerberus == NULL) || (cmd_mctp == NULL) || (device_mgr == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	memset (mctp, 0, sizeof (struct mctp_interface));

#ifdef CMD_ENABLE_ISSUE_REQUEST
	status = platform_semaphore_init (&mctp->wait_for_response);
	if (status != 0) {
		return status;
	}

	status = platform_mutex_init (&mctp->lock);
	if (status != 0) {
		platform_semaphore_free (&mctp->wait_for_response);
		return status;
	}
#endif

	mctp->device_manager = device_mgr;
	mctp->cmd_cerberus = cmd_cerberus;
	mctp->cmd_mctp = cmd_mctp;

	mctp->req_buffer.data =
		&mctp->msg_buffer[sizeof (mctp->msg_buffer) - MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY];
	mctp->resp_buffer.data = mctp->msg_buffer;

	return 0;
}

/**
 * MCTP interface deinitialization
 *
 * @param mctp The MCTP interface to deinitialize
 */
void mctp_interface_deinit (struct mctp_interface *mctp)
{
	if (mctp != NULL) {
#ifdef CMD_ENABLE_ISSUE_REQUEST
		platform_semaphore_free (&mctp->wait_for_response);
		platform_mutex_free (&mctp->lock);
#endif
	}
}

/**
 * Assign a channel ID to the mctp interface
 *
 * @param mctp The MCTP interface to assign the channel id.
 * @param channel_id The channel ID to associate with this interface.
 *
 * @return 0 if the channel was successfully initialized or an error code.
 */
int mctp_interface_set_channel_id (struct mctp_interface *mctp, int channel_id)
{
	if (mctp == NULL) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	mctp->channel_id = channel_id;

	return 0;
}

/**
 * Generate packets for full MCTP message from payload
 *
 * @param device_mgr Device manager instance to utilize
 * @param payload Buffer with payload bytes
 * @param payload_len Length of payload bytes
 * @param buf Buffer to fill with generated MCTP packets
 * @param max_buf_len Maximum length of buf
 * @param dest_eid EID to address packets to
 * @param dest_addr SMBus address to address packets to
 * @param src_eid EID of source device
 * @param src_addr SMBus address of source device
 * @param msg_tag MCTP message tag to utilize
 * @param tag_owner MCTP tag owner to utilize
 * @param max_packet_len Buffer to fill with length of a full MCTP packet
 *
 * @return Generated MCTP message length if success or an error code.
 */
static int mctp_interface_generate_packets_from_payload (struct device_manager *device_mgr,
	uint8_t *payload, size_t payload_len, uint8_t *buf, size_t max_buf_len, uint8_t dest_eid,
	uint8_t dest_addr, uint8_t src_eid, uint8_t src_addr, uint8_t msg_tag, uint8_t tag_owner,
	size_t *max_packet_len)
{
	uint8_t packet_seq = 0;
	size_t max_packet_payload;
	size_t num_packets;
	size_t packet_payload_len;
	size_t i_payload = 0;
	size_t i_buf = 0;
	size_t i_packet;
	bool som = true;
	bool eom;
	int status;

	max_packet_payload = device_manager_get_max_transmission_unit_by_eid (device_mgr, dest_eid);
	num_packets = MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (payload_len, max_packet_payload);

	for (i_packet = 0; i_packet < num_packets; ++i_packet) {
		eom = (i_packet == (num_packets - 1));
		packet_payload_len = (payload_len > max_packet_payload) ? max_packet_payload : payload_len;

		status = mctp_base_protocol_construct (&payload[i_payload], packet_payload_len, &buf[i_buf],
			max_buf_len - i_buf, src_addr, dest_eid, src_eid, som, eom, packet_seq, msg_tag,
			tag_owner, dest_addr);
		if (ROT_IS_ERROR (status)) {
			return status;
		}

		if (som) {
			*max_packet_len = status;
		}

		i_buf += status;
		i_payload += packet_payload_len;
		payload_len -= packet_payload_len;

		som = false;
		packet_seq = (packet_seq + 1) % 4;
	}

	return i_buf;
}

/**
 * Construct an MCTP packet for an error response.
 *
 * @param mctp MCTP interface instance.
 * @param cerberus_eid EID of Cerberus device.
 * @param packets Output for the buffer containing the error message.
 * @param error_code Identifier for the error.
 * @param error_data Data for the error condition.
 * @param src_eid EID of the original message source.
 * @param dest_eid EID of the original message destination.
 * @param msg_tag Tag of the original message.
 * @param response_addr SMBUS address to respond to.
 * @param source_addr SMBUS address responding from.
 * @param cmd_set Command set to respond on.
 * @param tag_owner Tag owner of incoming message.
 *
 * @return 0 if the packet was successfully constructed or an error code.
 */
static int mctp_interface_generate_error_packet (struct mctp_interface *mctp, int cerberus_eid,
	struct cmd_message **message, uint8_t error_code, uint32_t error_data, uint8_t src_eid,
	uint8_t dest_eid, uint8_t msg_tag, uint8_t response_addr, uint8_t source_addr, uint8_t cmd_set,
	uint8_t tag_owner)
{
	int status;

	if (error_code != CERBERUS_PROTOCOL_NO_ERROR) {
		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_CHANNEL, mctp->channel_id, 0);
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_PROTOCOL_ERROR,
			(error_code << 24 | src_eid << 16 | dest_eid << 8 | msg_tag), error_data);
	}

	if ((dest_eid != cerberus_eid) || (tag_owner == MCTP_BASE_PROTOCOL_TO_RESPONSE)) {
		return 0;
	}

	mctp_interface_reset_message_processing (mctp);

	mctp->req_buffer.max_response = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;
	status = mctp->cmd_cerberus->generate_error_packet (mctp->cmd_cerberus, &mctp->req_buffer,
		error_code, error_data, cmd_set);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	if (mctp->req_buffer.length > MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT) {
		return MCTP_BASE_PROTOCOL_MSG_TOO_LARGE;
	}

	status = mctp_base_protocol_construct (mctp->req_buffer.data, mctp->req_buffer.length,
		mctp->resp_buffer.data, sizeof (mctp->msg_buffer), source_addr, src_eid, dest_eid, true,
		true, 0, msg_tag, MCTP_BASE_PROTOCOL_TO_RESPONSE, response_addr);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	mctp->resp_buffer.msg_size = status;
	mctp->resp_buffer.pkt_size = status;
	mctp->resp_buffer.dest_addr = response_addr;

	*message = &mctp->resp_buffer;
	return 0;
}

/**
 * MCTP interface message processing function
 *
 * @param mctp MCTP interface instance
 * @param rx_packet The received packet to process
 * @param tx_message Output for a response message to send.  This pointer MUST NOT be freed by the
 * caller.
 *
 * @return Completion status, 0 if success or an error code.
 */
int mctp_interface_process_packet (struct mctp_interface *mctp, struct cmd_packet *rx_packet,
	struct cmd_message **tx_message)
{
	struct cerberus_protocol_header *header;
	uint32_t msg1 = 0;
	uint32_t msg2 = 0;
	uint8_t i_byte;
	uint8_t *payload;
	uint8_t source_addr;
	uint8_t src_eid;
	uint8_t dest_eid;
	uint8_t msg_tag;
	uint8_t packet_seq;
	uint8_t crc;
	uint8_t response_addr;
	uint8_t cmd_set = 0;
	uint8_t tag_owner;
	size_t payload_len;
	bool som;
	bool eom;
	int cerberus_eid;
	int status;

	if ((mctp == NULL) || (rx_packet == NULL) || (tx_message == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	cerberus_eid = device_manager_get_device_eid (mctp->device_manager,
		DEVICE_MANAGER_SELF_DEVICE_NUM);
	if (ROT_IS_ERROR (cerberus_eid)) {
		return cerberus_eid;
	}

	*tx_message = NULL;

	status = mctp_base_protocol_interpret (rx_packet->data, rx_packet->pkt_size,
		rx_packet->dest_addr, &source_addr, &som, &eom, &src_eid, &dest_eid, &payload, &payload_len,
		&msg_tag, &packet_seq, &crc, &mctp->msg_type, &tag_owner);

	response_addr = source_addr;

	if (status != 0) {
		msg2 = rx_packet->pkt_size << 24;
		for (i_byte = 0; i_byte < 7; ++i_byte) {
			if (i_byte < 4) {
				msg1 |= (rx_packet->data[i_byte] << (i_byte * 8));
			}
			else {
				msg2 |= (rx_packet->data[i_byte] << ((i_byte - 4) * 8));
			}
		}

		debug_log_create_entry (DEBUG_LOG_SEVERITY_INFO, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_CHANNEL, mctp->channel_id, 0);
		debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
			MCTP_LOGGING_PKT_DROPPED, msg1, msg2);

		if ((status == MCTP_BASE_PROTOCOL_INVALID_MSG) ||
			(status == MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG)) {
			return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
				CERBERUS_PROTOCOL_ERROR_INVALID_REQ, status, src_eid, dest_eid, msg_tag,
				response_addr, rx_packet->dest_addr, cmd_set, tag_owner);
		}
		else if (status == MCTP_BASE_PROTOCOL_BAD_CHECKSUM) {
			return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
				CERBERUS_PROTOCOL_ERROR_INVALID_CHECKSUM, crc, src_eid, dest_eid, msg_tag,
				response_addr, rx_packet->dest_addr, cmd_set, tag_owner);
		}
		else {
			mctp_interface_reset_message_processing (mctp);
			return status;
		}
	}

	if ((dest_eid != cerberus_eid) && (dest_eid != MCTP_BASE_PROTOCOL_NULL_EID)) {
		return 0;
	}

	if (tag_owner == MCTP_BASE_PROTOCOL_TO_RESPONSE) {
		if (!mctp->response_expected || (src_eid != mctp->response_eid) ||
			(msg_tag != mctp->response_msg_tag)) {
			return MCTP_BASE_PROTOCOL_UNEXPECTED_PKT;
		}
	}

	if (som) {
		mctp->req_buffer.length = 0;
		mctp->req_buffer.source_eid = src_eid;
		mctp->req_buffer.source_addr = source_addr;
		mctp->req_buffer.target_eid = dest_eid;
		mctp->start_packet_len = payload_len;
		mctp->req_buffer.channel_id = mctp->channel_id;
		mctp->packet_seq = 0;
		mctp->msg_tag = msg_tag;
	}
	else if (mctp->start_packet_len == 0) {
		// If this packet is not a SOM, and we haven't received a SOM packet yet
		return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
			CERBERUS_PROTOCOL_ERROR_OUT_OF_ORDER_MSG, 0, src_eid, dest_eid, msg_tag, response_addr,
			rx_packet->dest_addr, cmd_set, tag_owner);
	}
	else if (packet_seq != mctp->packet_seq) {
		return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
			CERBERUS_PROTOCOL_ERROR_OUT_OF_SEQ_WINDOW, 0, src_eid, dest_eid, msg_tag, response_addr,
			rx_packet->dest_addr, cmd_set, tag_owner);
	}
	else if (msg_tag != mctp->msg_tag) {
		return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
			CERBERUS_PROTOCOL_ERROR_INVALID_REQ, 0, src_eid, dest_eid, msg_tag, response_addr,
			rx_packet->dest_addr, cmd_set, tag_owner);
	}
	else if (src_eid != mctp->req_buffer.source_eid) {
		return 0;
	}
	else {
		if (((int) payload_len != mctp->start_packet_len) &&
		   !(eom && ((int) payload_len < mctp->start_packet_len))) {
			// Can only have different size than SOM if EOM and smaller than SOM
			return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
				CERBERUS_PROTOCOL_ERROR_INVALID_PACKET_LEN, payload_len, src_eid, dest_eid, msg_tag,
				response_addr, rx_packet->dest_addr, cmd_set, tag_owner);
		}
	}

	if ((payload_len + mctp->req_buffer.length) > MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY) {
		return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
			CERBERUS_PROTOCOL_ERROR_MSG_OVERFLOW, payload_len + mctp->req_buffer.length,
			src_eid, dest_eid, msg_tag, response_addr, rx_packet->dest_addr, cmd_set, tag_owner);
	}

	// Assemble packets into message and process message when EOM is received
	memcpy (&mctp->req_buffer.data[mctp->req_buffer.length], payload, payload_len);
	mctp->req_buffer.length += payload_len;
	mctp->packet_seq = (mctp->packet_seq + 1) % 4;

	if (eom) {
		if (tag_owner == MCTP_BASE_PROTOCOL_TO_RESPONSE) {
#ifdef CMD_ENABLE_ISSUE_REQUEST
			/* If flag is not defined, we will never issue requests, so response_expected will
			 * always be false and any response packets will be rejected in the earlier check.
			 * Therefore, we dont need to do anything here in that case. */
			if (MCTP_BASE_PROTOCOL_IS_CONTROL_MSG (mctp->msg_type)) {
				status = mctp->cmd_mctp->process_response (mctp->cmd_mctp, &mctp->req_buffer);

				debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
					MCTP_LOGGING_MCTP_CONTROL_RSP_FAIL, status, mctp->channel_id);
			}
			else {
				status = mctp->cmd_cerberus->process_response (mctp->cmd_cerberus,
					&mctp->req_buffer);
			}

			mctp->response_expected = false;
			mctp->response_msg_tag = (mctp->response_msg_tag + 1) % 8;

			platform_semaphore_post (&mctp->wait_for_response);

			return status;
#endif
		}
		/* We know the message is one of the two supported types by this point.  If it wasn't, it
		 * would have failed earlier in packet processing. */
		else if (MCTP_BASE_PROTOCOL_IS_CONTROL_MSG (mctp->msg_type)) {
			if (tag_owner == MCTP_BASE_PROTOCOL_TO_REQUEST) {
				mctp->req_buffer.max_response = MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT;

				status = mctp->cmd_mctp->process_request (mctp->cmd_mctp, &mctp->req_buffer);
				if (status != 0) {
					debug_log_create_entry (DEBUG_LOG_SEVERITY_ERROR, DEBUG_LOG_COMPONENT_MCTP,
						MCTP_LOGGING_MCTP_CONTROL_REQ_FAIL, status, mctp->channel_id);

					return status;
				}
			}
		}
		else if (MCTP_BASE_PROTOCOL_IS_VENDOR_MSG (mctp->msg_type)) {
			header = (struct cerberus_protocol_header*) mctp->req_buffer.data;
			cmd_set = header->rq;

			mctp->req_buffer.max_response = device_manager_get_max_message_len_by_eid (
				mctp->device_manager, src_eid);
			status = mctp->cmd_cerberus->process_request (mctp->cmd_cerberus, &mctp->req_buffer);

			/* Regardless of the processing status, check to see if the timeout needs adjusting. */
			if (rx_packet->timeout_valid && mctp->req_buffer.crypto_timeout) {
				platform_increase_timeout (
					MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS -
						MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS, &rx_packet->pkt_timeout);
			}

			if (status != 0) {
				return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
					CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, status, src_eid, dest_eid, msg_tag,
					response_addr, rx_packet->dest_addr, cmd_set, tag_owner);
			}
			else if (mctp->req_buffer.length == 0) {
				return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
					CERBERUS_PROTOCOL_NO_ERROR, status, src_eid, dest_eid, msg_tag, response_addr,
					rx_packet->dest_addr, cmd_set, tag_owner);
			}

			if (mctp->req_buffer.length >
				device_manager_get_max_message_len_by_eid (mctp->device_manager, src_eid)) {
				return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
					CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, MCTP_BASE_PROTOCOL_MSG_TOO_LARGE, src_eid,
					dest_eid, msg_tag, response_addr, rx_packet->dest_addr, cmd_set, tag_owner);
			}
		}
		else {
			/* Handle other messages types, such as SPDM. */
		}

		if (mctp->req_buffer.length > 0) {
			status = mctp_interface_generate_packets_from_payload (mctp->device_manager,
				mctp->req_buffer.data, mctp->req_buffer.length, mctp->resp_buffer.data,
				sizeof (mctp->msg_buffer), mctp->req_buffer.source_eid, response_addr,
				mctp->req_buffer.target_eid, rx_packet->dest_addr, mctp->msg_tag,
				MCTP_BASE_PROTOCOL_TO_RESPONSE, &mctp->resp_buffer.pkt_size);
			if (ROT_IS_ERROR (status)) {
				if (MCTP_BASE_PROTOCOL_IS_VENDOR_MSG (mctp->req_buffer.data[0])) {
					return mctp_interface_generate_error_packet (mctp, cerberus_eid, tx_message,
						CERBERUS_PROTOCOL_ERROR_UNSPECIFIED, status, src_eid, dest_eid, msg_tag,
						response_addr, rx_packet->dest_addr, cmd_set, tag_owner);
				}
				else {
					return status;
				}
			}

			mctp->resp_buffer.msg_size = status;
			mctp->resp_buffer.dest_addr = response_addr;
			mctp->req_buffer.length = 0;

			*tx_message = &mctp->resp_buffer;
		}
		else {
			*tx_message = NULL;
		}
	}

	return 0;
}

/**
 * Reset the MCTP layer.  This discards previously received packets and begins looking for a new
 * message.
 *
 * @param mctp The MCTP layer to reset.
 */
void mctp_interface_reset_message_processing (struct mctp_interface *mctp)
{
	mctp->req_buffer.length = 0;
	mctp->start_packet_len = 0;
}

#ifdef CMD_ENABLE_ISSUE_REQUEST
/**
 * Packetize a request message and send it over a command channel.  This call will block until the
 * full message has been transmitted and a response has been received or the operation times out.
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
 * @param timeout_ms Timeout period in milliseconds to wait for response to be received.
 *
 * @return 0 if the request was transmitted successfully or an error code.
 */
int mctp_interface_issue_request (struct mctp_interface *mctp, struct cmd_channel *channel,
	uint8_t dest_addr, uint8_t dest_eid, uint8_t *request, size_t length, uint8_t *msg_buffer,
	size_t max_length, uint32_t timeout_ms)
{
	struct cmd_message cmd_msg;
	size_t max_transmission_unit;
	size_t num_packets;
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

	status = mctp_interface_generate_packets_from_payload (mctp->device_manager, request, length,
		msg_buffer, max_length, dest_eid, dest_addr, src_eid, src_addr, mctp->response_msg_tag,
		MCTP_BASE_PROTOCOL_TO_REQUEST, &cmd_msg.pkt_size);
	if (ROT_IS_ERROR (status)) {
		return status;
	}

	cmd_msg.msg_size = status;
	cmd_msg.data = msg_buffer;
	cmd_msg.dest_addr = dest_addr;

	platform_mutex_lock (&mctp->lock);

	mctp->response_expected = true;
	mctp->response_eid = dest_eid;

	status = platform_semaphore_reset (&mctp->wait_for_response);
	if (status != 0) {
		goto exit;
	}

	status = cmd_channel_send_message (channel, &cmd_msg);
	if (status != 0) {
		goto exit;
	}

	status = platform_semaphore_wait (&mctp->wait_for_response, timeout_ms);
	if (status == 1) {
		status = MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT;
	}

exit:
	mctp->response_msg_tag = (mctp->response_msg_tag + 1) % 8;
	mctp->response_expected = false;
	platform_mutex_unlock (&mctp->lock);

	return status;
}
#endif
