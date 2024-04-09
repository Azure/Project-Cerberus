// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "crypto/checksum.h"
#include "mctp_base_protocol.h"


/**
 * Parse an MCTP packet header and determine if the packet is valid.
 *
 * As long as the buffer contains at least the MCTP transport header, details will be parsed into
 * the output parameters even in the case of an error.  Payload and CRC details will only be
 * available if the packet was parsed successfully.
 *
 * @param buf Packet to parse.
 * @param buf_len Total length of the packet.
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
 * @param msg_type Output for the packet message type.  This will only be populated if the packet is
 * the start of a new message.
 * @param tag_owner Output for the packet tag owner field.
 *
 * @return Completion status, 0 if success or an error code.
 */
int mctp_base_protocol_interpret (const uint8_t *buf, size_t buf_len, uint8_t dest_addr,
	uint8_t *source_addr, bool *som, bool *eom, uint8_t *src_eid, uint8_t *dest_eid,
	const uint8_t **payload, size_t *payload_len, uint8_t *msg_tag, uint8_t *packet_seq,
	uint8_t *crc, uint8_t *msg_type, uint8_t *tag_owner)
{
	const struct mctp_base_protocol_transport_header *header =
		(const struct mctp_base_protocol_transport_header*) buf;
	size_t packet_len;

	if ((buf == NULL) || (source_addr == NULL) || (som == NULL) || (eom == NULL) ||
		(src_eid == NULL) || (dest_eid == NULL) || (payload == NULL) || (payload_len == NULL) ||
		(msg_tag == NULL) || (packet_seq == NULL) || (crc == NULL) || (msg_type == NULL) ||
		(tag_owner == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	if (buf_len < sizeof (struct mctp_base_protocol_transport_header)) {
		return MCTP_BASE_PROTOCOL_PKT_TOO_SHORT;
	}

	/* There at least exists a transport header, so parse out those details. */
	*source_addr = (header->source_addr >> 1);
	*dest_eid = header->destination_eid;
	*src_eid = header->source_eid;
	*som = header->som;
	*eom = header->eom;
	*packet_seq = header->packet_seq;
	*msg_tag = header->msg_tag;
	*tag_owner = header->tag_owner;

	/* Check that the packet is well formed. */
	if ((header->cmd_code != SMBUS_CMD_CODE_MCTP) || (header->rsvd != 0) ||
		(header->header_version != MCTP_BASE_PROTOCOL_SUPPORTED_HDR_VERSION) ||
		(header->destination_eid == header->source_eid)) {
		return MCTP_BASE_PROTOCOL_INVALID_PKT;
	}

	/* While MCTP requires that all packets contain the optional PEC byte, not all implementations
	 * follow this requirement, so treat the PEC as optional.  The PEC byte will be checked if it's
	 * present, but parsing will not fail if it's not present. */
	packet_len = header->byte_count + MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD_NO_PEC;

	/* A packet must contain a payload, so one that only contains a header is invalid.  This check
	 * ensures there is at least one byte of payload. */
	if (packet_len <= sizeof (struct mctp_base_protocol_transport_header)) {
		return MCTP_BASE_PROTOCOL_PKT_TOO_SHORT;
	}

	/* Confirm that the packet length does not overflow the buffer containing the packet. */
	if (buf_len < packet_len) {
		return MCTP_BASE_PROTOCOL_PKT_LENGTH_MISMATCH;
	}

	*payload = &buf[sizeof (struct mctp_base_protocol_transport_header)];
	*payload_len = packet_len - sizeof (struct mctp_base_protocol_transport_header);

	if (header->som) {
		const struct mctp_base_protocol_message_header *msg_header =
			(const struct mctp_base_protocol_message_header*) *payload;

		*msg_type = msg_header->msg_type;
	}

	if (buf_len > packet_len) {
		/* There are extra bytes in the buffer beyond the packet length.  The packet contains a PEC
		 * byte that must be checked.*/
		*crc = checksum_crc8 ((dest_addr << 1), buf, packet_len);
		if (*crc != buf[packet_len]) {
			return MCTP_BASE_PROTOCOL_BAD_CHECKSUM;
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
 *
 * @return Packet length if completed successfully or an error code.
 */
int mctp_base_protocol_construct (const uint8_t *buf, size_t buf_len, uint8_t *out_buf,
	size_t out_buf_len, uint8_t source_addr, uint8_t dest_eid, uint8_t source_eid, bool som,
	bool eom, uint8_t packet_seq, uint8_t msg_tag, uint8_t tag_owner, uint8_t dest_addr)
{
	struct mctp_base_protocol_transport_header *header =
		(struct mctp_base_protocol_transport_header*) out_buf;
	size_t msg_offset = sizeof (struct mctp_base_protocol_transport_header);
	size_t out_len;

	if ((buf == NULL) || (out_buf == NULL)) {
		return MCTP_BASE_PROTOCOL_INVALID_ARGUMENT;
	}

	if ((buf_len == 0) || (buf_len > MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT)) {
		return MCTP_BASE_PROTOCOL_BAD_BUFFER_LENGTH;
	}

	out_len = mctp_protocol_packet_len (buf_len);

	if (out_buf_len < out_len) {
		return MCTP_BASE_PROTOCOL_BUF_TOO_SMALL;
	}

	memmove (&out_buf[msg_offset], buf, buf_len);
	memset (header, 0, sizeof (struct mctp_base_protocol_transport_header));

	header->cmd_code = SMBUS_CMD_CODE_MCTP;
	header->byte_count = out_len - MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD;
	header->source_addr = (source_addr << 1) | 0x01;
	header->header_version = MCTP_BASE_PROTOCOL_SUPPORTED_HDR_VERSION;
	header->destination_eid = dest_eid;
	header->source_eid = source_eid;
	header->som = (som) ? 1 : 0;
	header->eom = (eom) ? 1 : 0;
	header->packet_seq = packet_seq;
	header->msg_tag = msg_tag;
	header->tag_owner = tag_owner;

	out_buf[msg_offset + buf_len] = checksum_crc8 ((dest_addr << 1), out_buf,
		out_len - MCTP_BASE_PROTOCOL_PEC_SIZE);

	return out_len;
}
