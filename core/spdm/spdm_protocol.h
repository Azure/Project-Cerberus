// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_PROTOCOL_H_
#define SPDM_PROTOCOL_H_

#include <stdint.h>
#include "platform_config.h"
#include "mctp/mctp_base_protocol.h"

/* Configurable SPDM protocol parameters. Defaults can be overridden in platform_config.h */

/**
 * Maximum supported transfer size for SPDM 1.0 and 1.1 messages.
 */
#ifndef SPDM_1_0_AND_1_1_MAX_RESPONSE_LEN
#define SPDM_1_0_AND_1_1_MAX_RESPONSE_LEN			MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY
#endif

/**
 * Minimum length for any SPDM message.
 */
#define SPDM_PROTOCOL_MIN_MSG_LEN					(sizeof (struct spdm_protocol_header))

/**
 * Maximum amount of payload data that can be carried in an SPDM message over MCTP.
 */
#define SPDM_PROTOCOL_MAX_MCTP_PAYLOAD_PER_MSG      \
	(MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY - (sizeof (struct mctp_base_protocol_message_header)))

#define SPDM_NONCE_LEN								32

#define SPDM_MAJOR_VERSION							1
#define SPDM_MIN_MINOR_VERSION						0
#define SPDM_MAX_MINOR_VERSION						2

#define SPDM_MAX_RESPONSE_TIMEOUT_MS				100

/**
 * Create an SPDM version from major and minor versions.
 *
 * @param max_ver SPDM major version.
 * @param min_ver SPDM minor version.
 */
#define SPDM_MAKE_VERSION(major, minor)		((major << 4) | minor)

/**
 * Supported SPDM versions.
 */
#define SPDM_VERSION_1_0		SPDM_MAKE_VERSION (1, 0)
#define SPDM_VERSION_1_1		SPDM_MAKE_VERSION (1, 1)
#define SPDM_VERSION_1_2		SPDM_MAKE_VERSION (1, 2)

/**
 * Get SPDM major version.
 *
 * @param version SPDM version.
 */
#define SPDM_GET_MAJOR_VERSION(version) ((((uint8_t) version) >> 4))

/**
 * Get SPDM minor version.
 *
 * @param version SPDM version.
 */
#define SPDM_GET_MINOR_VERSION(version) ((((uint8_t) version) & 0xF))

/**
 * SPDM 1.2 signature prefix context.
 */
#define SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT		"dmtf-spdm-v1.2.*"
#define SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_SIZE \
	(sizeof (SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT) - 1)
#define SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_MAJOR_VERSION_OFFSET		11
#define SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_MINOR_VERSION_OFFSET		13
#define SPDM_VERSION_1_2_SIGNING_PREFIX_CONTEXT_ASTERIX_OFFSET				15

/**
 * SPDM 1.2 signature context max. buffer size.
 */
#define SPDM_VERSION_1_2_SIGNING_CONTEXT_SIZE		100

/**
 * SPDM CHALLENGE_AUTH signature context.
 */
#define SPDM_CHALLENGE_AUTH_SIGN_CONTEXT			"responder-challenge_auth signing"
#define SPDM_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE		(sizeof(SPDM_CHALLENGE_AUTH_SIGN_CONTEXT) - 1)
#define SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT		"requester-challenge_auth signing"
#define SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT_SIZE   \
		(sizeof(SPDM_MUT_CHALLENGE_AUTH_SIGN_CONTEXT) - 1)

/**
 * SPDM MEASUREMENTS signature context.
 */
#define SPDM_MEASUREMENTS_SIGN_CONTEXT				"responder-measurements signing"
#define SPDM_MEASUREMENTS_SIGN_CONTEXT_SIZE			(sizeof(SPDM_MEASUREMENTS_SIGN_CONTEXT) - 1)

/**
 * SPDM KEY_EXCHANGE signature context.
 */
#define SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT		"responder-key_exchange_rsp signing"
#define SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT_SIZE \
	(sizeof(SPDM_KEY_EXCHANGE_RESPONSE_SIGN_CONTEXT) - 1)

#define SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT		"Requester-KEP-dmtf-spdm-v1.2"
#define SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT_SIZE \
	(sizeof(SPDM_VERSION_1_2_KEY_EXCHANGE_REQUESTER_CONTEXT) - 1)

#define SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT		"Responder-KEP-dmtf-spdm-v1.2"
#define SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT_SIZE \
	(sizeof(SPDM_VERSION_1_2_KEY_EXCHANGE_RESPONDER_CONTEXT) - 1)

/**
 * SPDM FINISH signature context.
 */
#define SPDM_FINISH_SIGN_CONTEXT		"requester-finish signing"
#define SPDM_FINISH_SIGN_CONTEXT_SIZE	(sizeof(SPDM_FINISH_SIGN_CONTEXT) - 1)

#pragma pack(push, 1)
/**
 * Header that is added to SPDM messages when using the MCTP binding.
 *
 * TODO:  This shouldn't be needed anymore, replaced with mctp_base_protocol_message_header and new
 * message handling (for both request and response messages).  See if it can be removed to avoid
 * duplication.
 */
struct spdm_protocol_mctp_header {
	uint8_t msg_type:7;			/**< Identifier for the type of message. */
	uint8_t integrity_check:1;	/**< Flag indicating if an integrity check has been added. */
};

/**
 * SPDM portion of packet header
 */
struct spdm_protocol_header {
	uint8_t spdm_minor_version:4;	/**< SPDM specification minor version used for the message. */
	uint8_t spdm_major_version:4;	/**< SPDM specification major version used for the message. */
	uint8_t req_rsp_code;			/**< Request/Response code for the message. */
};

#pragma pack(pop)

/**
 * SPDM protocol request/response codes
 */
enum {
	SPDM_RESPONSE_GET_DIGESTS = 0x01,					/**< Response with certificate chain digests */
	SPDM_RESPONSE_GET_CERTIFICATE = 0x02,				/**< Response with certificate chains */
	SPDM_RESPONSE_CHALLENGE = 0x03,						/**< Challenge-response protocol response */
	SPDM_RESPONSE_GET_VERSION = 0x04,					/**< SPDM specification version of device */
	SPDM_RESPONSE_GET_MEASUREMENTS = 0x60,				/**< Response with measurements from device */
	SPDM_RESPONSE_GET_CAPABILITIES = 0x61,				/**< SPDM capabilities of device */
	SPDM_RESPONSE_NEGOTIATE_ALGORITHMS = 0x63,			/**< Negotiate cryptographic algorithms */
	SPDM_RESPONSE_KEY_EXCHANGE = 0x64,					/**< Response for a initiate key exchange session establishment flow request */
	SPDM_RESPONSE_FINISH = 0x65,						/**< Response for a complete key exchange session establishment flow request */
	SPDM_RESPONSE_PSK_EXCHANGE = 0x66,					/**< Response for a initiate pre-shared key session establishment flow request */
	SPDM_RESPONSE_PSK_FINISH = 0x67,					/**< Response for a complete pre-shared key session establishment request */
	SPDM_RESPONSE_HEARTBEAT = 0x68,						/**< Keep session alive response */
	SPDM_RESPONSE_KEY_UPDATE = 0x69,					/**< Update session keys response */
	SPDM_RESPONSE_GET_ENCAPSULATED_REQUEST = 0x6a,		/**< Response with request from device */
	SPDM_RESPONSE_DELIVER_ENCAPSULATED_RESPONSE = 0x6b,	/**< Response to response sent to device */
	SPDM_RESPONSE_END_SESSION = 0x6c,					/**< Terminate session response */
	SPDM_RESPONSE_VENDOR_DEFINED_REQUEST = 0x7e,		/**< Unique vendor defined response */
	SPDM_RESPONSE_ERROR = 0x7f,							/**< Error response message */
	SPDM_REQUEST_GET_DIGESTS = 0x81,					/**< Retrieve certificate chain digests */
	SPDM_REQUEST_GET_CERTIFICATE = 0x82,				/**< Retrieve certificate chains */
	SPDM_REQUEST_CHALLENGE = 0x83,						/**< Authenticate device using challenge-response protocol */
	SPDM_REQUEST_GET_VERSION = 0x84,					/**< Get SPDM specification version of device */
	SPDM_REQUEST_GET_MEASUREMENTS = 0xe0,				/**< Retrieve measurements from device */
	SPDM_REQUEST_GET_CAPABILITIES = 0xe1,				/**< Get SPDM capabilities of device */
	SPDM_REQUEST_NEGOTIATE_ALGORITHMS = 0xe3,			/**< Negotiate cryptographic algorithms */
	SPDM_REQUEST_KEY_EXCHANGE = 0xe4,					/**< Initiate key exchange session establishment flow */
	SPDM_REQUEST_FINISH = 0xe5,							/**< Complete key exchange session establishment flow */
	SPDM_REQUEST_PSK_EXCHANGE = 0xe6,					/**< Initiate pre-shared key session establishment flow */
	SPDM_REQUEST_PSK_FINISH = 0xe7,						/**< Complete pre-shared key session establishment */
	SPDM_REQUEST_HEARTBEAT = 0xe8,						/**< Keep session alive */
	SPDM_REQUEST_KEY_UPDATE = 0xe9,						/**< Update session keys */
	SPDM_REQUEST_GET_ENCAPSULATED_REQUEST = 0xea,		/**< Get request from device */
	SPDM_REQUEST_DELIVER_ENCAPSULATED_RESPONSE = 0xeb,	/**< Send back response to device */
	SPDM_REQUEST_END_SESSION = 0xec,					/**< Terminate session */
	SPDM_REQUEST_VENDOR_DEFINED_REQUEST = 0xfe,			/**< Unique vendor defined request */
	SPDM_REQUEST_RESPOND_IF_READY = 0xff,				/**< Request response from device */
};


#endif	/* SPDM_PROTOCOL_H_ */
