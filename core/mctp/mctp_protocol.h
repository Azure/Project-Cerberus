// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_PROTOCOL_H_
#define MCTP_PROTOCOL_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "platform_config.h"


/* Configurable MCTP protocol parameters.  Defaults can be overridden in platform_config.h. */
#ifndef MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT
#define MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT			247
#endif
#ifndef	MCTP_PROTOCOL_MAX_MESSAGE_BODY
#define MCTP_PROTOCOL_MAX_MESSAGE_BODY				4096
#endif
#ifndef MCTP_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS
#define MCTP_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS		100
#endif
#ifndef MCTP_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS
#define MCTP_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS			1000
#endif


#define	MCTP_PROTOCOL_MAX_CERBERUS_MESSAGE_BODY		4096
#define	MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT			64
#if MCTP_PROTOCOL_MAX_MESSAGE_BODY > MCTP_PROTOCOL_MAX_CERBERUS_MESSAGE_BODY
#error "Invalid MCTP maximum message length."
#endif
#if MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT < MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT
#error "Invalid MCTP maximum transmission unit length."
#endif
#if MCTP_PROTOCOL_MAX_MESSAGE_BODY < MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT
#error "Improperly configured MCTP message/packet lengths."
#endif


/**
 * Find the maximum number of packets for specified message length.
 *
 * @param msg Total message length
 * @param pkt Length of each packet
 */
#define	MCTP_PROTOCOL_PACKETS_IN_MESSAGE(msg, pkt)	((msg + pkt - 1) / pkt)

/**
 * Find the packetized MCTP message length for a specified payload length.
 *
 * @param num_packets Number of packets in message
 * @param payload_len Payload length transmitted in message
 */
#define MCTP_PROTOCOL_MESSAGE_LEN(num_packets, payload_len) \
	(num_packets * MCTP_PROTOCOL_PACKET_OVERHEAD + payload_len)

/**
 * Code at beginning of MCTP packet indicating SMBus binding.
 */
#define SMBUS_CMD_CODE_MCTP							0x0F

/**
 * The number of bytes used for packet error checking.
 */
#define MCTP_PROTOCOL_PEC_SIZE						1

/**
 * The number of overhead bytes in an MCTP packet, including both SMBus and MCTP overhead.
 */
#define MCTP_PROTOCOL_PACKET_OVERHEAD				(sizeof (struct mctp_protocol_transport_header) + MCTP_PROTOCOL_PEC_SIZE)

/**
 * The smallest encapsulated MCTP packet length, assuming the smallest payload size required by MCTP spec.
 */
#define	MCTP_PROTOCOL_MIN_PACKET_LEN				(MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT + MCTP_PROTOCOL_PACKET_OVERHEAD)

/**
 * The maximum MCTP packet length assuming SMBus binding.
 */
#define MCTP_PROTOCOL_MAX_PACKET_LEN				(MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT + MCTP_PROTOCOL_PACKET_OVERHEAD)

/**
 * The minimum length of a packetized and encapsulated MCTP message.
 */
#define	MCTP_PROTOCOL_MIN_MESSAGE_LEN				MCTP_PROTOCOL_MIN_PACKET_LEN

/**
 * The maximum buffer length needed to hold a packetized message using SMBus binding of maximum length.
 */
#define	MCTP_PROTOCOL_MAX_MESSAGE_LEN				\
	(MCTP_PROTOCOL_PACKETS_IN_MESSAGE (MCTP_PROTOCOL_MAX_MESSAGE_BODY, MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT) * MCTP_PROTOCOL_MIN_PACKET_LEN)

/**
 * The number of packets needed to packetize a maximum sized message using the maximum transmission unit size.
 */
#define	MCTP_PROTOCOL_MAX_PACKET_PER_MAX_SIZED_MESSAGE		\
	(MCTP_PROTOCOL_PACKETS_IN_MESSAGE (MCTP_PROTOCOL_MAX_MESSAGE_BODY, MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT))

/**
 * The minimum size of an MCTP control message.
 */
#define MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN			(sizeof (struct mctp_protocol_control_header))

/**
 * The minimum size of an MCTP control response message.
 */
#define MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN		(sizeof (struct mctp_protocol_control_header) + MCTP_PROTOCOL_PEC_SIZE)

/**
 * The size of a MCTP control response message with a failed completion code.
 */
#define MCTP_PROTOCOL_CONTROL_FAILURE_REPONSE_LEN	MCTP_PROTOCOL_MIN_CONTROL_MSG_RSP_LEN

/********************
 * MCTP header fields
 ********************/

/* Explained in section 8.1 of the MCTP Base Specification DSP0236 */
#define MCTP_PROTOCOL_MSG_TYPE_SHIFT				0
#define MCTP_PROTOCOL_MSG_TYPE_SET_MASK				(0x7F << MCTP_PROTOCOL_MSG_TYPE_SHIFT)

#define MCTP_PROTOCOL_SUPPORTED_HDR_VERSION			0x01
#define MCTP_PROTOCOL_TO_REQUEST					0x01
#define MCTP_PROTOCOL_TO_RESPONSE					0x00

#define MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG			0x00
#define MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF			0x7E

#define MCTP_PROTOCOL_VID_FORMAT_PCI				0

#define	MCTP_PROTOCOL_IS_CONTROL_MSG(x)				(((x) & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_CONTROL_MSG)
#define	MCTP_PROTOCOL_IS_VENDOR_MSG(x)				(((x) & MCTP_PROTOCOL_MSG_TYPE_SET_MASK) == MCTP_PROTOCOL_MSG_TYPE_VENDOR_DEF)

/**
 * Number of SMBus overhead bytes.
 */
#define MCTP_PROTOCOL_SMBUS_OVERHEAD				(2 + MCTP_PROTOCOL_PEC_SIZE)

/**
 * Number of SMBus overhead bytes without PEC byte.
 */
#define MCTP_PROTOCOL_SMBUS_OVERHEAD_NO_PEC			(MCTP_PROTOCOL_SMBUS_OVERHEAD - MCTP_PROTOCOL_PEC_SIZE)


/**
 * MCTP default EIDs per the Cerberus Protocol
 */
enum
{
	MCTP_PROTOCOL_IB_EXT_MGMT = 0x08,				/**< In-band external management EID */
	MCTP_PROTOCOL_OOB_EXT_MGMT = 0x09,				/**< Out-of-band external management EID */
	MCTP_PROTOCOL_BMC_EID = 0x0A,					/**< BMC EID */
	MCTP_PROTOCOL_PA_ROT_CTRL_EID = 0x0B,			/**< Cerberus PA RoT control EID */
};

/**
 * MCTP control commands
 * Listed in section 10.1 of the MCTP Base Specification DSP0236
 */
enum {
	MCTP_PROTOCOL_SET_EID = 0x01,					/**< Set Endpoint ID */
	MCTP_PROTOCOL_GET_EID = 0x02,					/**< Get Endpoint ID */
	MCTP_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT = 0x06,	/**< Get vendor defined message support */
};

/**
 * MCTP completion codes
 */
enum
{
	MCTP_PROTOCOL_SUCCESS,							/**< Success */
	MCTP_PROTOCOL_ERROR,							/**< Generic error */
	MCTP_PROTOCOL_ERROR_INVALID_DATA = 3,			/**< Invalid data or parameter value */
	MCTP_PROTOCOL_ERROR_INVALID_LEN,				/**< Invalid message length */
	MCTP_PROTOCOL_ERROR_NOT_READY = 0xF0,			/**< Receiver not ready */
	MCTP_PROTOCOL_ERROR_UNSUPPORTED_CMD,			/**< Command unspecified or unsupported */
	MCTP_PROTOCOL_CMD_SPECIFIC,						/**< Command specific completion code */
};


#pragma pack(push, 1)
/**
 * MCTP portion of packet header
 */
struct mctp_protocol_transport_header
{
	uint8_t cmd_code;								/**< SMBUS command code */
	uint8_t byte_count;								/**< SMBUS packet byte count */
	uint8_t source_addr;							/**< SMBUS source address */
	uint8_t header_version:4;						/**< MCTP header version */
	uint8_t rsvd:4;									/**< Reserved, zero */
	uint8_t destination_eid;						/**< MCTP destination EID */
	uint8_t source_eid;								/**< MCTP source EID */
	uint8_t msg_tag:3;								/**< MCTP message tag */
	uint8_t tag_owner:1;							/**< MCTP tag owner */
	uint8_t packet_seq:2;							/**< MCTP packet sequence */
	uint8_t eom:1;									/**< MCTP end of message */
	uint8_t som:1;									/**< MCTP start of message */
};

/**
 * Control message portion of packet header
 */
struct mctp_protocol_control_header
{
	uint8_t msg_type:7;								/**< MCTP message type */
	uint8_t integrity_check:1;						/**< MCTP message integrity check, always 0 */
	uint8_t instance_id:5;							/**< Instance ID */
	uint8_t rsvd:1;									/**< Reserved */
	uint8_t d_bit:1;								/**< D-bit */
	uint8_t rq:1;									/**< Request bit */
	uint8_t command_code;							/**< Command code */
};
#pragma pack(pop)

/**
 * Get the total packet length of an MCTP packet.
 *
 * @param payload_len The MCTP packet payload length
 */
#define	mctp_protocol_packet_len(payload_len)		(MCTP_PROTOCOL_PACKET_OVERHEAD + payload_len)

/**
 * Get the payload length of an MCTP packet from the packet length.
 *
 * @param packet_len The MCTP packet length
 */
#define	mctp_protocol_payload_len(packet_len) 		(packet_len - MCTP_PROTOCOL_PACKET_OVERHEAD)


int mctp_protocol_interpret (uint8_t *buf, size_t buf_len, uint8_t smbus_addr, uint8_t *source_addr,
	bool *som, bool *eom, uint8_t *src_eid, uint8_t *dest_eid, uint8_t** payload,
	size_t* payload_len, uint8_t *msg_tag, uint8_t *packet_seq, uint8_t *crc, uint8_t* msg_type,
	uint8_t *tag_owner);
int mctp_protocol_construct (uint8_t *buf, size_t buf_len, uint8_t *out_buf, size_t out_buf_len,
	uint8_t source_addr, uint8_t dest_eid, uint8_t source_eid, bool som, bool eom,
	uint8_t packet_seq, uint8_t msg_tag, uint8_t tag_owner, uint8_t dest_addr);


#define	MCTP_PROTOCOL_ERROR(code)		ROT_ERROR (ROT_MODULE_MCTP_PROTOCOL, code)

/**
 * Error codes that can be generated by the MCTP protocol handler.
 */
enum {
	MCTP_PROTOCOL_INVALID_ARGUMENT = MCTP_PROTOCOL_ERROR (0x00),	/**< Input parameter is null or not valid. */
	MCTP_PROTOCOL_NO_MEMORY = MCTP_PROTOCOL_ERROR (0x01),			/**< Memory allocation failed. */
	MCTP_PROTOCOL_NO_SOM = MCTP_PROTOCOL_ERROR (0x02),				/**< A packet was received without a SOM. */
	MCTP_PROTOCOL_UNEXPECTED_PKT = MCTP_PROTOCOL_ERROR (0x03),		/**< A packet was received that doesn't match the context for the current message. */
	MCTP_PROTOCOL_BAD_LENGTH = MCTP_PROTOCOL_ERROR (0x04),			/**< The received packet was not the expected length. */
	MCTP_PROTOCOL_MSG_TOO_LARGE = MCTP_PROTOCOL_ERROR (0x05),		/**< The message is bigger than the maximum supported size. */
	MCTP_PROTOCOL_INVALID_MSG = MCTP_PROTOCOL_ERROR (0x06),			/**< An invalid message was received. */
	MCTP_PROTOCOL_BAD_CHECKSUM = MCTP_PROTOCOL_ERROR (0x07),		/**< The message checksum is bad. */
	MCTP_PROTOCOL_MSG_TOO_SHORT = MCTP_PROTOCOL_ERROR (0x08),		/**< The received packet was shorter than the minimum length. */
	MCTP_PROTOCOL_BAD_BUFFER_LENGTH = MCTP_PROTOCOL_ERROR (0x09),	/**< The packet buffer is an invalid size. */
	MCTP_PROTOCOL_BUF_TOO_SMALL = MCTP_PROTOCOL_ERROR (0x0a),		/**< Provided buffer too small for output. */
	MCTP_PROTOCOL_UNSUPPORTED_MSG = MCTP_PROTOCOL_ERROR (0x0b),		/**< Received packet format not supported. */
	MCTP_PROTOCOL_INVALID_EID = MCTP_PROTOCOL_ERROR (0x0c),			/**< Received packet from device using incorrect EID. */
	MCTP_PROTOCOL_BUILD_UNSUPPORTED = MCTP_PROTOCOL_ERROR (0x0d),	/**< Failed to construct a packet for an unsupported message type. */
	MCTP_PROTOCOL_RESPONSE_TIMEOUT = MCTP_PROTOCOL_ERROR (0x0e),	/**< Timeout elapsed before receiving a response. */
};


#endif /* MCTP_PROTOCOL_H_ */
