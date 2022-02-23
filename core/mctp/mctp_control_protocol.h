// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef MCTP_CONTROL_PROTOCOL_H_
#define MCTP_CONTROL_PROTOCOL_H_

#include <stdint.h>
#include <stdbool.h>
#include "status/rot_status.h"
#include "platform_config.h"


/**
 * The minimum size of an MCTP control message.
 */
#define MCTP_CONTROL_PROTOCOL_MIN_MSG_LEN					(sizeof (struct mctp_control_protocol_header))

/**
 * The minimum size of an MCTP control response message.
 */
#define MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN				(sizeof (struct mctp_control_protocol_header) + MCTP_BASE_PROTOCOL_PEC_SIZE)

/**
 * The size of a MCTP control response message with a failed completion code.
 */
#define MCTP_CONTROL_PROTOCOL_FAILURE_RESP_LEN				MCTP_CONTROL_PROTOCOL_MIN_MSG_RSP_LEN

/**
 * MCTP control protocol version information.
 */
#define MCTP_CONTROL_PROTOCOL_MAJOR_VERSION					1
#define MCTP_CONTROL_PROTOCOL_MINOR_VERSION					1
#define MCTP_CONTROL_PROTOCOL_UPDATE_VERSION				0


/**
 * MCTP control commands
 * Listed in section 10.1 of the MCTP Base Specification DSP0236
 */
enum {
	MCTP_CONTROL_PROTOCOL_SET_EID = 0x01,					/**< Set Endpoint ID */
	MCTP_CONTROL_PROTOCOL_GET_EID = 0x02,					/**< Get Endpoint ID */
	MCTP_CONTROL_PROTOCOL_GET_MCTP_VERSION = 0x04,			/**< Get MCTP Version Support */
	MCTP_CONTROL_PROTOCOL_GET_MESSAGE_TYPE = 0x05,			/**< Get Message Type Support */
	MCTP_CONTROL_PROTOCOL_GET_VEN_DEF_MSG_SUPPORT = 0x06,	/**< Get Vendor Defined Message Support */
	MCTP_CONTROL_PROTOCOL_GET_ROUTING_TABLE_ENTRIES = 0x0A,	/**< Get Routing Table Entries */
};

/**
 * MCTP completion codes
 * Listed in section 10.2 of the MCTP Base Specification DSP0236
 */
enum
{
	MCTP_CONTROL_PROTOCOL_SUCCESS,							/**< Success */
	MCTP_CONTROL_PROTOCOL_ERROR,							/**< Generic error */
	MCTP_CONTROL_PROTOCOL_ERROR_INVALID_DATA = 0x03,		/**< Invalid data or parameter value */
	MCTP_CONTROL_PROTOCOL_ERROR_INVALID_LEN,				/**< Invalid message length */
	MCTP_CONTROL_PROTOCOL_ERROR_NOT_READY = 0xF0,			/**< Receiver not ready */
	MCTP_CONTROL_PROTOCOL_ERROR_UNSUPPORTED_CMD,			/**< Command unspecified or unsupported */
	MCTP_CONTROL_PROTOCOL_CMD_SPECIFIC,						/**< Command specific completion code */
};


#pragma pack(push, 1)
/**
 * Control message portion of packet header
 */
struct mctp_control_protocol_header
{
	uint8_t msg_type:7;										/**< MCTP message type */
	uint8_t integrity_check:1;								/**< MCTP message integrity check, always 0 */
	uint8_t instance_id:5;									/**< Instance ID */
	uint8_t rsvd:1;											/**< Reserved */
	uint8_t d_bit:1;										/**< D-bit */
	uint8_t rq:1;											/**< Request bit */
	uint8_t command_code;									/**< Command code */
};
#pragma pack(pop)


#endif /* MCTP_CONTROL_PROTOCOL_H_ */
