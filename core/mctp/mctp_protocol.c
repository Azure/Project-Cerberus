// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "crypto/checksum.h"
#include "mctp_protocol.h"


/**
 * Check for valid MCTP packet
 *
 * @param buf Transaction packet contents
 * @param buf_len Length of transaction packet contents
 * @param source_addr Source SMBUS address
 * @param som Output boolean indicating if packet is a start of a MCTP message
 * @param eom Output boolean indicating if packet is an end of a MCTP message
 * @param src_eid Output indicating the source EID of the message
 * @param dest_eid Output indicating the destination EID of the message
 * @param payload Output pointer to start of payload
 * @param payload_len Output payload size
 * @param msg_tag Output message tag
 * @param packet_seq Output packet sequence
 * @param crc Output CRC calculation
 * @param smbus_addr Cerberus SMBUS address
 * @param msg_type Buffer for message type. If SOM will be populated with message type, else
 * 	incoming value will be used.
 *
 * @return Completion status, 0 if success or an error code.
 */
int mctp_protocol_interpret (uint8_t *buf, size_t buf_len, uint8_t *source_addr, bool *som,
	bool *eom, uint8_t *src_eid, uint8_t *dest_eid, uint8_t** payload, size_t* payload_len,
	uint8_t *msg_tag, uint8_t *packet_seq, uint8_t *crc, uint8_t smbus_addr, uint8_t *msg_type)
{
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	size_t packet_len;

	if ((buf == NULL) || (source_addr == NULL) || (som == NULL) || (eom == NULL) ||
		(src_eid == NULL) || (dest_eid == NULL) || (payload == NULL) || (payload_len == NULL) ||
		(msg_tag == NULL) || (packet_seq == NULL) || (crc == NULL) || (msg_type == NULL)) {
		return MCTP_PROTOCOL_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct mctp_protocol_transport_header)) {
		return MCTP_PROTOCOL_MSG_TOO_SHORT;
	}

	*source_addr = (header->source_addr >> 1);
	*dest_eid = header->destination_eid;
	*src_eid = header->source_eid;
	*som = header->som;
	*eom = header->eom;
	*packet_seq = header->packet_seq;
	*msg_tag = header->msg_tag;
	*payload = &buf[sizeof (struct mctp_protocol_transport_header)];

	if (header->som) {
		*msg_type = (*payload)[0];
	}

	if ((*msg_type & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG) {
		packet_len = header->byte_count + 2;
		*payload_len = packet_len - sizeof (struct mctp_protocol_transport_header);
	}
	else if ((*msg_type & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) ==
		MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF) {
		packet_len = header->byte_count + 3;
		*payload_len = packet_len - sizeof (struct mctp_protocol_transport_header) - 1;

		*crc = checksum_crc8 ((smbus_addr << 1), buf, packet_len - 1);

		if (*crc != buf[packet_len - 1]) {
			return MCTP_PROTOCOL_BAD_CHECKSUM;
		}
	}
	else {
		return MCTP_PROTOCOL_UNSUPPORTED_MSG;
	}

	if ((header->cmd_code != SMBUS_CMD_CODE_MCTP) || (buf_len < packet_len) ||
		(header->rsvd != 0)) {
		return MCTP_PROTOCOL_INVALID_MSG;
	}

	if (header->header_version != MCTP_PROTOCOL_SUPPORTED_HDR_VERSION) {
		return MCTP_PROTOCOL_UNSUPPORTED_MSG;
	}

	return 0;
}

/**
 * Construct an MCTP response packet
 *
 * @param buf Payload
 * @param buf_len Payload length
 * @param out_buf Output packet buffer
 * @param out_buf_len Maximum buffer length
 * @param source_addr Source address
 * @param dest_eid Destination EID
 * @param source_eid Source EID
 * @param som Boolean indicating that packet will be the start of a message
 * @param eom Boolean indicating that packet will be the end of a message
 * @param packet_seq Packet sequence number
 * @param msg_tag Message tag
 * @param tag_owner Initiator of MCTP transaction
 * @param dest_addr Destination SMBUS address
 * @param msg_type Buffer for message type. If SOM will be populated with message type, else
 * 	incoming value will be used.
 *
 * @return Packet length if completed successfully or an error code.
 */
int mctp_protocol_construct (uint8_t *buf, size_t buf_len, uint8_t *out_buf, size_t out_buf_len,
	uint8_t source_addr, uint8_t dest_eid, uint8_t source_eid, bool som, bool eom,
	uint8_t packet_seq, uint8_t msg_tag, uint8_t tag_owner, uint8_t dest_addr, uint8_t *msg_type)
{
	struct mctp_protocol_transport_header *header =
		(struct mctp_protocol_transport_header*) out_buf;
	size_t msg_offset = sizeof (struct mctp_protocol_transport_header);
	size_t out_len;
	bool crc;

	if ((buf == NULL) || (out_buf == NULL) || (msg_type == NULL)) {
		return MCTP_PROTOCOL_INVALID_ARGUMENT;
	}

	if ((buf_len == 0) || (buf_len > MCTP_PROTOCOL_MAX_PAYLOAD_PER_PKT)) {
		return MCTP_PROTOCOL_BAD_BUFFER_LENGTH;
	}

	if (som) {
		*msg_type = buf[0];
	}

	if ((*msg_type & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG) {
		crc = false;
	}
	else if ((*msg_type & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF) {
		crc = true;
	}
	else {
		return MCTP_PROTOCOL_UNSUPPORTED_MSG;
	}

	out_len = msg_offset + buf_len + crc;

	if (out_buf_len < out_len) {
		return MCTP_PROTOCOL_BUF_TOO_SMALL;
	}

	memset (header, 0, sizeof (struct mctp_protocol_transport_header));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = out_len - (crc ? 3 : 2);
	header->source_addr = (source_addr << 1) | 0x01;
	header->header_version = MCTP_PROTOCOL_SUPPORTED_HDR_VERSION;
	header->destination_eid = dest_eid;
	header->source_eid = source_eid;
	header->som = (som ? 1 : 0);
	header->eom = (eom ? 1 : 0);
	header->packet_seq = packet_seq;
	header->msg_tag = msg_tag;
	header->tag_owner = tag_owner;

	memcpy (&out_buf[msg_offset], buf, buf_len);

	if (crc) {
		out_buf[msg_offset + buf_len] = checksum_crc8 ((dest_addr << 1), out_buf, out_len - 1);
	}

	return out_len;
}
