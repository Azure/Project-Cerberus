// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "crypto/checksum.h"
#include "mctp_protocol.h"


/**
 * Parse an MCTP packet header and determine if the packet is valid.
 *
 * @param buf Packet to parse.
 * @param buf_len Total lengtnh of the packet.
 * @param dest_addr Destination SMBUS address.
 * @param source_addr Output for the source SMBUS address.
 * @param som Output boolean indicating if packet is a start of an MCTP message.
 * @param eom Output boolean indicating if packet is the end of an MCTP message.
 * @param src_eid Output indicating the source EID of the message.
 * @param dest_eid Output indicating the destination EID of the message.
 * @param payload Output pointer to start of the packet payload.
 * @param payload_len Output for the payload length.
 * @param msg_tag Output for the message tag.
 * @param packet_seq Output for the packet sequence.
 * @param crc Output for the packet CRC.
 * @param msg_type The message type. If the packet indicates SOM, this will be populated with the
 * parsed message type, otherwise the specified type will be used for parsing.
 *
 * @return Completion status, 0 if success or an error code.
 */
int mctp_protocol_interpret (uint8_t *buf, size_t buf_len, uint8_t dest_addr, uint8_t *source_addr,
	bool *som, bool *eom, uint8_t *src_eid, uint8_t *dest_eid, uint8_t **payload,
	size_t *payload_len, uint8_t *msg_tag, uint8_t *packet_seq, uint8_t *crc, uint8_t *msg_type)
{
	struct mctp_protocol_transport_header *header = (struct mctp_protocol_transport_header*) buf;
	size_t packet_len;
	bool add_crc = true;

	if ((buf == NULL) || (source_addr == NULL) || (som == NULL) || (eom == NULL) ||
		(src_eid == NULL) || (dest_eid == NULL) || (payload == NULL) || (payload_len == NULL) ||
		(msg_tag == NULL) || (packet_seq == NULL) || (crc == NULL) || (msg_type == NULL)) {
		return MCTP_PROTOCOL_INVALID_ARGUMENT;
	}

	if (buf_len <= sizeof (struct mctp_protocol_transport_header)) {
		return MCTP_PROTOCOL_MSG_TOO_SHORT;
	}

	if (header->byte_count <= sizeof (struct mctp_protocol_transport_header)) {
		/* Prevent payload_len underflow caused by manipulated header->byte_count. */
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

	if (MCTP_PROTOCOL_IS_CONTROL_MSG (*msg_type)) {
		/* Control messages do not contain a CRC on the packet. */
		packet_len = header->byte_count + 2;
		*payload_len = packet_len - sizeof (struct mctp_protocol_transport_header);
		add_crc = false;
	}
	else if (MCTP_PROTOCOL_IS_VENDOR_MSG (*msg_type)) {
		packet_len = header->byte_count + 3;
		*payload_len = packet_len - sizeof (struct mctp_protocol_transport_header) - 1;
	}
	else {
		return MCTP_PROTOCOL_UNSUPPORTED_MSG;
	}

	if ((header->cmd_code != SMBUS_CMD_CODE_MCTP) || (buf_len < packet_len) ||
		(header->rsvd != 0) || (*dest_eid == *src_eid)) {
		return MCTP_PROTOCOL_INVALID_MSG;
	}

	if (header->header_version != MCTP_PROTOCOL_SUPPORTED_HDR_VERSION) {
		return MCTP_PROTOCOL_UNSUPPORTED_MSG;
	}

	if (add_crc) {
		*crc = checksum_crc8 ((dest_addr << 1), buf, packet_len - 1);
		if (*crc != buf[packet_len - 1]) {
			return MCTP_PROTOCOL_BAD_CHECKSUM;
		}
	}

	return 0;
}

/**
 * Construct an MCTP packet.
 *
 * @param buf Payload for the packet.
 * @param buf_len Length of the payload.
 * @param out_buf Output for the constructed packet.  It is allowed to have the output buffer
 * overlap the input buffer.
 * @param out_buf_len Maximum constructed packet length.
 * @param source_addr Source SMBus address.
 * @param dest_eid Destination EID for the packet.
 * @param source_eid Source EID of the packet.
 * @param som Boolean indicating that packet will be the start of a message.
 * @param eom Boolean indicating that packet will be the end of a message.
 * @param packet_seq Packet sequence number.
 * @param msg_tag Message tag.
 * @param tag_owner Initiator of the MCTP transaction.
 * @param dest_addr Destination SMBUS address.
 * @param msg_type The message type.  If creating a SOM packet, this will be populated with the
 * message type, otherwise the specified type will be used for packet construction.
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

	if ((buf_len == 0) || (buf_len > MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT)) {
		return MCTP_PROTOCOL_BAD_BUFFER_LENGTH;
	}

	if (som) {
		*msg_type = buf[0];
	}

	if (MCTP_PROTOCOL_IS_CONTROL_MSG (*msg_type)) {
		/* Control messages do not contain a CRC on the packet. */
		crc = false;
	}
	else if (MCTP_PROTOCOL_IS_VENDOR_MSG (*msg_type)) {
		crc = true;
	}
	else {
		return MCTP_PROTOCOL_BUILD_UNSUPPORTED;
	}

	out_len = msg_offset + buf_len + crc;

	if (out_buf_len < out_len) {
		return MCTP_PROTOCOL_BUF_TOO_SMALL;
	}

	memmove (&out_buf[msg_offset], buf, buf_len);
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

	if (crc) {
		out_buf[msg_offset + buf_len] = checksum_crc8 ((dest_addr << 1), out_buf, out_len - 1);
	}

	return out_len;
}
