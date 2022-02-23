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


#endif /* PLATFORM_CONFIG_H_ */
