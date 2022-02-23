// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_BASE_PROTOCOL_H_
#define MCTP_BASE_PROTOCOL_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "platform_config.h"


/* Configurable MCTP protocol parameters.  Defaults can be overridden in platform_config.h. */
#ifndef MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT
#define MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT			247
#endif
#ifndef	MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY
#define MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY					4096
#endif
#ifndef MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS
#define MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS			100
#endif
#ifndef MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS
#define MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS			1000
#endif


#define	MCTP_BASE_PROTOCOL_MAX_CERBERUS_MESSAGE_BODY		4096
#define	MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT			64
#if MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY > MCTP_BASE_PROTOCOL_MAX_CERBERUS_MESSAGE_BODY
#error "Invalid MCTP maximum message length."
#endif
#if MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT < MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT
#error "Invalid MCTP maximum transmission unit length."
#endif
#if MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY < MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT
#error "Improperly configured MCTP message/packet lengths."
#endif


/**
 * Find the maximum number of packets for specified message length.
 *
 * @param msg Total message length
 * @param pkt Length of each packet
 */
#define	MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE(msg, pkt)		((msg + pkt - 1) / pkt)

/**
 * Find the packetized MCTP message length for a specified payload length.
 *
 * @param num_packets Number of packets in message
 * @param payload_len Payload length transmitted in message
 */
#define MCTP_BASE_PROTOCOL_MESSAGE_LEN(num_packets, payload_len) \
	(num_packets * MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + payload_len)

/**
 * Code at beginning of MCTP packet indicating SMBus binding.
 */
#define SMBUS_CMD_CODE_MCTP									0x0F

/**
 * The number of bytes used for packet error checking.
 */
#define MCTP_BASE_PROTOCOL_PEC_SIZE							1

/**
 * The number of overhead bytes in an MCTP packet, including both SMBus and MCTP overhead.
 */
#define MCTP_BASE_PROTOCOL_PACKET_OVERHEAD					(sizeof (struct mctp_base_protocol_transport_header) + MCTP_BASE_PROTOCOL_PEC_SIZE)

/**
 * The smallest encapsulated MCTP packet length, assuming the smallest payload size required by MCTP spec.
 */
#define	MCTP_BASE_PROTOCOL_MIN_PACKET_LEN					(MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD)

/**
 * The maximum MCTP packet length assuming SMBus binding.
 */
#define MCTP_BASE_PROTOCOL_MAX_PACKET_LEN					(MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT + MCTP_BASE_PROTOCOL_PACKET_OVERHEAD)

/**
 * The minimum length of a packetized and encapsulated MCTP message.
 */
#define	MCTP_BASE_PROTOCOL_MIN_MESSAGE_LEN					MCTP_BASE_PROTOCOL_MIN_PACKET_LEN

/**
 * The maximum buffer length needed to hold a packetized message using SMBus binding of maximum length.
 */
#define	MCTP_BASE_PROTOCOL_MAX_MESSAGE_LEN				\
	(MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, MCTP_BASE_PROTOCOL_MIN_TRANSMISSION_UNIT) * MCTP_BASE_PROTOCOL_MIN_PACKET_LEN)

/**
 * The number of packets needed to packetize a maximum sized message using the maximum transmission unit size.
 */
#define	MCTP_BASE_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE		\
	(MCTP_BASE_PROTOCOL_PACKETS_IN_MESSAGE (MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY, MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT))

/**
 * MCTP base specification version information.
 */
#define MCTP_BASE_PROTOCOL_MAJOR_VERSION					1
#define MCTP_BASE_PROTOCOL_MINOR_VERSION					1
#define MCTP_BASE_PROTOCOL_UPDATE_VERSION					0


/********************
 * MCTP header fields
 ********************/

/* Explained in section 8.1 of the MCTP Base Specification DSP0236 */
#define MCTP_BASE_PROTOCOL_MSG_TYPE_SHIFT					0
#define MCTP_BASE_PROTOCOL_MSG_TYPE_SET_MASK				(0x7F << MCTP_BASE_PROTOCOL_MSG_TYPE_SHIFT)

#define MCTP_BASE_PROTOCOL_SUPPORTED_HDR_VERSION			0x01
#define MCTP_BASE_PROTOCOL_TO_REQUEST						0x01
#define MCTP_BASE_PROTOCOL_TO_RESPONSE						0x00

#define MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG				0x00
#define MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF				0x7E

#define MCTP_BASE_PROTOCOL_VID_FORMAT_PCI					0

#define	MCTP_BASE_PROTOCOL_IS_CONTROL_MSG(x)				(((x) & MCTP_BASE_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_BASE_PROTOCOL_MSG_TYPE_CONTROL_MSG)
#define	MCTP_BASE_PROTOCOL_IS_VENDOR_MSG(x)					(((x) & MCTP_BASE_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_BASE_PROTOCOL_MSG_TYPE_VENDOR_DEF)

/**
 * Number of SMBus overhead bytes.
 */
#define MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD					(2 + MCTP_BASE_PROTOCOL_PEC_SIZE)

/**
 * Number of SMBus overhead bytes without PEC byte.
 */
#define MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD_NO_PEC			(MCTP_BASE_PROTOCOL_SMBUS_OVERHEAD - MCTP_BASE_PROTOCOL_PEC_SIZE)


/**
 * MCTP default EIDs per the Cerberus Protocol
 */
enum
{
	MCTP_BASE_PROTOCOL_NULL_EID = 0x00,						/**< Null EID */
	MCTP_BASE_PROTOCOL_IB_EXT_MGMT = 0x08,					/**< In-band external management EID */
	MCTP_BASE_PROTOCOL_OOB_EXT_MGMT = 0x09,					/**< Out-of-band external management EID */
	MCTP_BASE_PROTOCOL_BMC_EID = 0x0A,						/**< BMC EID */
	MCTP_BASE_PROTOCOL_PA_ROT_CTRL_EID = 0x0B,				/**< Cerberus PA RoT control EID */
	MCTP_BASE_PROTOCOL_BROADCAST_EID = 0xFF,				/**< Broadcast EID */
};


#pragma pack(push, 1)
/**
 * MCTP portion of packet header
 */
struct mctp_base_protocol_transport_header
{
	uint8_t cmd_code;										/**< SMBUS command code */
	uint8_t byte_count;										/**< SMBUS packet byte count */
	uint8_t source_addr;									/**< SMBUS source address */
	uint8_t header_version:4;								/**< MCTP header version */
	uint8_t rsvd:4;											/**< Reserved, zero */
	uint8_t destination_eid;								/**< MCTP destination EID */
	uint8_t source_eid;										/**< MCTP source EID */
	uint8_t msg_tag:3;										/**< MCTP message tag */
	uint8_t tag_owner:1;									/**< MCTP tag owner */
	uint8_t packet_seq:2;									/**< MCTP packet sequence */
	uint8_t eom:1;											/**< MCTP end of message */
	uint8_t som:1;											/**< MCTP start of message */
};
#pragma pack(pop)

/**
 * Get the total packet length of an MCTP packet.
 *
 * @param payload_len The MCTP packet payload length
 */
#define	mctp_protocol_packet_len(payload_len)				(MCTP_BASE_PROTOCOL_PACKET_OVERHEAD + payload_len)

/**
 * Get the payload length of an MCTP packet from the packet length.
 *
 * @param packet_len The MCTP packet length
 */
#define	mctp_protocol_payload_len(packet_len) 				(packet_len - MCTP_BASE_PROTOCOL_PACKET_OVERHEAD)


int mctp_base_protocol_interpret (uint8_t *buf, size_t buf_len, uint8_t smbus_addr,
	uint8_t *source_addr, bool *som, bool *eom, uint8_t *src_eid, uint8_t *dest_eid,
	uint8_t** payload, size_t* payload_len, uint8_t *msg_tag, uint8_t *packet_seq, uint8_t *crc,
	uint8_t* msg_type, uint8_t *tag_owner);
int mctp_base_protocol_construct (uint8_t *buf, size_t buf_len, uint8_t *out_buf,
	size_t out_buf_len, uint8_t source_addr, uint8_t dest_eid, uint8_t source_eid, bool som,
	bool eom, uint8_t packet_seq, uint8_t msg_tag, uint8_t tag_owner, uint8_t dest_addr);


#define	MCTP_BASE_PROTOCOL_ERROR(code)						ROT_ERROR (ROT_MODULE_MCTP_BASE_PROTOCOL, code)

/**
 * Error codes that can be generated by the MCTP protocol handler.
 */
enum {
	MCTP_BASE_PROTOCOL_INVALID_ARGUMENT = MCTP_BASE_PROTOCOL_ERROR (0x00),	/**< Input parameter is null or not valid. */
	MCTP_BASE_PROTOCOL_NO_MEMORY = MCTP_BASE_PROTOCOL_ERROR (0x01),			/**< Memory allocation failed. */
	MCTP_BASE_PROTOCOL_NO_SOM = MCTP_BASE_PROTOCOL_ERROR (0x02),			/**< A packet was received without a SOM. */
	MCTP_BASE_PROTOCOL_UNEXPECTED_PKT = MCTP_BASE_PROTOCOL_ERROR (0x03),	/**< A packet was received that doesn't match the context for the current message. */
	MCTP_BASE_PROTOCOL_BAD_LENGTH = MCTP_BASE_PROTOCOL_ERROR (0x04),		/**< The received packet was not the expected length. */
	MCTP_BASE_PROTOCOL_MSG_TOO_LARGE = MCTP_BASE_PROTOCOL_ERROR (0x05),		/**< The message is bigger than the maximum supported size. */
	MCTP_BASE_PROTOCOL_INVALID_MSG = MCTP_BASE_PROTOCOL_ERROR (0x06),		/**< An invalid message was received. */
	MCTP_BASE_PROTOCOL_BAD_CHECKSUM = MCTP_BASE_PROTOCOL_ERROR (0x07),		/**< The message checksum is bad. */
	MCTP_BASE_PROTOCOL_MSG_TOO_SHORT = MCTP_BASE_PROTOCOL_ERROR (0x08),		/**< The received packet was shorter than the minimum length. */
	MCTP_BASE_PROTOCOL_BAD_BUFFER_LENGTH = MCTP_BASE_PROTOCOL_ERROR (0x09),	/**< The packet buffer is an invalid size. */
	MCTP_BASE_PROTOCOL_BUF_TOO_SMALL = MCTP_BASE_PROTOCOL_ERROR (0x0a),		/**< Provided buffer too small for output. */
	MCTP_BASE_PROTOCOL_UNSUPPORTED_MSG = MCTP_BASE_PROTOCOL_ERROR (0x0b),	/**< Received packet format not supported. */
	MCTP_BASE_PROTOCOL_INVALID_EID = MCTP_BASE_PROTOCOL_ERROR (0x0c),		/**< Received packet from device using incorrect EID. */
	MCTP_BASE_PROTOCOL_BUILD_UNSUPPORTED = MCTP_BASE_PROTOCOL_ERROR (0x0d),	/**< Failed to construct a packet for an unsupported message type. */
	MCTP_BASE_PROTOCOL_RESPONSE_TIMEOUT = MCTP_BASE_PROTOCOL_ERROR (0x0e),	/**< Timeout elapsed before receiving a response. */
};


#endif /* MCTP_BASE_PROTOCOL_H_ */
