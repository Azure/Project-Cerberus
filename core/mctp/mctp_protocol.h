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

#define	MCTP_PROTOCOL_PACKETS_IN_MESSAGE(msg, pkt)	((msg + pkt - 1) / pkt)

#define SMBUS_CMD_CODE_MCTP							0x0F

#define MCTP_PROTOCOL_PACKET_OVERHEAD				(sizeof (struct mctp_protocol_transport_header) + 1)
#define	MCTP_PROTOCOL_MIN_PACKET_LEN				(MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT + MCTP_PROTOCOL_PACKET_OVERHEAD)
#define MCTP_PROTOCOL_MAX_PACKET_LEN				(MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT + MCTP_PROTOCOL_PACKET_OVERHEAD)
#define	MCTP_PROTOCOL_MIN_MESSAGE_LEN				MCTP_PROTOCOL_MIN_PACKET_LEN
#define	MCTP_PROTOCOL_MAX_MESSAGE_LEN				\
	(MCTP_PROTOCOL_PACKETS_IN_MESSAGE (MCTP_PROTOCOL_MAX_MESSAGE_BODY, MCTP_PROTOCOL_MIN_TRANSMISSION_UNIT) * MCTP_PROTOCOL_MIN_PACKET_LEN)
#define	MCTP_PROTOCOL_MAX_PACKET_PER_MESSAGE		\
	((MCTP_PROTOCOL_MAX_MESSAGE_BODY + MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT - 1) / MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT)

#define MCTP_PROTOCOL_MIN_CONTROL_MSG_LEN			(sizeof (struct mctp_protocol_control_header))

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
 * MCTP EIDs
 */
enum
{
	MCTP_PROTOCOL_IB_EXT_MGMT = 0x08,				/**< In-band external management EID */
	MCTP_PROTOCOL_OOB_EXT_MGMT = 0x09,				/**< Out-of-band external management EID */
	MCTP_PROTOCOL_BMC_EID = 0x0A,					/**< BMC EID */
	MCTP_PROTOCOL_PA_ROT_CTRL_EID = 0x0B,			/**< Cerberus PA RoT control EID */
	MCTP_PROTOCOL_TEST_DEVICE = 0x0C,				/**< Test device EID */
};

/**
 * MCTP control commands
 */
enum {
	MCTP_PROTOCOL_SET_EID = 0x01,					/**< Set Endpoint ID */
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


int mctp_protocol_interpret (uint8_t *buf, size_t buf_len, uint8_t smbus_addr, uint8_t *source_addr,
	bool *som, bool *eom, uint8_t *src_eid, uint8_t *dest_eid, uint8_t** payload,
	size_t* payload_len, uint8_t *msg_tag, uint8_t *packet_seq, uint8_t *crc, uint8_t* msg_type);
int mctp_protocol_construct (uint8_t *buf, size_t buf_len, uint8_t *out_buf, size_t out_buf_len,
	uint8_t source_addr, uint8_t dest_eid, uint8_t source_eid, bool som, bool eom,
	uint8_t packet_seq, uint8_t msg_tag, uint8_t tag_owner, uint8_t dest_addr, uint8_t* msg_type);


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
};


#endif /* MCTP_PROTOCOL_H_ */
