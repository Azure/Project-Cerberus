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
//#define	RSA_MAX_KEY_LENGTH		(4096 / 8)

/**
 * The maximum elliptic curve size supported by the ECC API.
 */
#define	ECC_MAX_KEY_LENGTH		521


/********************
 * MCTP protocol
 ********************/

/**
 * The maximum size for an outbound MCTP packet.
 */
//#define MCTP_PROTOCOL_MAX_PACKET_LEN					255

/**
 * The maximum total size for an MCTP message.
 */
//#define MCTP_PROTOCOL_MAX_MESSAGE_LEN					4224

/**
 * The maximum number of packets in a single message:
 * ceil (MCTP_PROTOCOL_MAX_MESSAGE_LEN / MCTP_PROTOCOL_MAX_PACKET_LEN)
 */
//#define MCTP_PROTOCOL_MAX_NUM_PACKETS_PER_MSG			17


#endif /* PLATFORM_CONFIG_H_ */
