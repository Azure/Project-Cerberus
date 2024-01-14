// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_CONFIG_H_
#define PLATFORM_CONFIG_H_


/* List of configuration parameters that can be specified for a given platform.  Undefined values
 * will use the default value. */


/*******************
 * Attestation
 *******************/

/**
 * The key bit length to use for auxiliary attestation.
 */
// #define	AUX_ATTESTATION_KEY_BITS			3072


/*****************************
 * Component attestation
 *****************************/

/**
 * Wait time before reattesting after device succeeds attestation, in milliseconds.
 */
// #define PCD_FLASH_ATTESTATION_SUCCESS_RETRY_DEFAULT					86400000

/**
 * Wait time before reattesting after device fails attestation, in milliseconds.
 */
// #define PCD_FLASH_ATTESTATION_FAIL_RETRY_DEFAULT						10000

/**
 * Wait time before retrying after device fails discovery, in milliseconds.
 */
// #define PCD_FLASH_DISCOVERY_FAIL_RETRY_DEFAULT						10000

/**
 * MCTP control protocol response timeout period, in milliseconds.
 */
// #define PCD_FLASH_MCTP_CTRL_TIMEOUT_DEFAULT							2000

/**
 * Wait time after RoT boots to send MCTP get table request, in millseconds. If 0, RoT only waits
 * for EID assignment.
 */
// #define PCD_FLASH_MCTP_BRIDGE_GET_TABLE_WAIT_DEFAULT					3000

/**
 * Additional time for timeout period due to MCTP bridge, in milliseconds.
 */
// #define PCD_FLASH_MCTP_BRIDGE_ADDITIONAL_TIMEOUT_DEFAULT				0

/**
 * Maximum duration to wait before retrying after receiving SPDM ResponseNotReady error, in
 * milliseconds.
 */
// #define PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_DURATION_DEFAULT		1000

/**
 * Maximum number of SPDM ResponseNotReady retries permitted by device.
 */
// #define PCD_FLASH_ATTESTATION_RSP_NOT_READY_MAX_RETRY_DEFAULT		3


/*************
 * Crypto
 *************/

/**
 * The maximum key length supported by the RSA API.
 */
// #define	RSA_MAX_KEY_LENGTH		RSA_KEY_LENGTH_4K

/**
 * The maximum elliptic curve size supported by the ECC API.
 */
// #define	ECC_MAX_KEY_LENGTH		ECC_KEY_LENGTH_521


/********************
 * MCTP protocol
 ********************/

/**
 * The maximum supported payload size for an MCTP packet.
 */
// #define MCTP_BASE_PROTOCOL_MAX_TRANSMISSION_UNIT				247

/**
 * The maximum supported body size for an MCTP message.
 */
// #define MCTP_BASE_PROTOCOL_MAX_MESSAGE_BODY					4096

/**
 * The maximum time allowed after receiving a completed request before the response must start
 * transmission.  The timeout is in milliseconds.
 */
// #define MCTP_BASE_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS			100

/**
 * The maximum time allowed after receiving a completed cryptographic request before the response
 * must start transmission.  This timeout is in milliseconds.
 */
// #define MCTP_BASE_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS				1000

/**
 * The VID set value to utilize in a Get Vendor Defined Message Support response.
 */
// #define CERBERUS_VID_SET_RESPONSE							0xFF


/********************
 * DOE protocol
 ********************/

/**
 * Maximum platform supported size of a DOE message.
 */
// #define DOE_MESSAGE_PLATFORM_MAX_SIZE_IN_BYTES		0x00100000


/********************
 * SPDM protocol
 ********************/

/**
 * Maximum number of SPDM sessions supported.
 */
// #define SPDM_MAX_SESSION_COUNT		1

/**
 * Buffer size for storing Version, Capabilities, Algorithms SPDM messages.
 */
// #define SPDM_TRANSCRIPT_MANAGER_VCA_BUFFER_MAX_SIZE		0x100


#endif /* PLATFORM_CONFIG_H_ */
