// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef PLATFORM_CONFIG_H_
#define PLATFORM_CONFIG_H_


/* List of configuration parameters that can be specified for a given platform.  Undefined values
 * will use the default value. */


/*************
 * Crypto
 *************/

/**
 * The maximum key length supported by the RSA API.
 */
// #define	RSA_MAX_KEY_LENGTH		(4096 / 8)

/**
 * The maximum elliptic curve size supported by the ECC API.
 */
// #define	ECC_MAX_KEY_LENGTH		521


/********************
 * MCTP protocol
 ********************/

/**
 * The maximum supported payload size for an MCTP packet.
 */
// #define MCTP_PROTOCOL_MAX_TRANSMISSION_UNIT				247

/**
 * The maximum supported body size for an MCTP message.
 */
// #define MCTP_PROTOCOL_MAX_MESSAGE_BODY					4096

/**
 * The maximum time allowed after receiving a completed request before the response must start
 * transmission.  The timout is in milliseconds.
 */
// #define MCTP_PROTOCOL_MAX_RESPONSE_TIMEOUT_MS			100

/**
 * The maximum time allowed after receiving a completed cryptographic request before the response
 * must start transmission.  This timeout is in milliseconds.
 */
// #define MCTP_PROTOCOL_MAX_CRYPTO_TIMEOUT_MS				1000


#endif /* PLATFORM_CONFIG_H_ */
