// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef SPDM_CERTIFICATE_CHAIN_DICE_STATIC_H_
#define SPDM_CERTIFICATE_CHAIN_DICE_STATIC_H_

#include "spdm_certificate_chain_dice.h"

/* Internal function declarations to allow for static initialization. */
int spdm_certificate_chain_dice_get_digest (const struct spdm_certificate_chain *chain,
	const struct hash_engine *hash, enum hash_type hash_type, uint8_t *digest, size_t length);
int spdm_certificate_chain_dice_get_certificate_chain (const struct spdm_certificate_chain *chain,
	const struct hash_engine *hash, enum hash_type root_ca_hash, size_t offset, uint8_t *buffer,
	size_t *length, size_t *total_length);
int spdm_certificate_chain_dice_sign_message (const struct spdm_certificate_chain *chain,
	const struct ecc_engine *ecc, const struct hash_engine *hash, enum hash_type hash_algo,
	const uint8_t *message, size_t msg_length, uint8_t *signature, size_t sig_length);


/**
 * Constant initializer for the SPDM certificate chain API.
 */
#define	SPDM_CERTIFICATE_CHAIN_DICE_API_INIT  { \
		.get_digest = spdm_certificate_chain_dice_get_digest, \
		.get_certificate_chain = spdm_certificate_chain_dice_get_certificate_chain, \
		.sign_message = spdm_certificate_chain_dice_sign_message, \
	}


/**
 * Initialize a static instance of a DICE certificate chain manager for SPDM.
 *
 * There is no validation done on the arguments.
 *
 * @param dice_certs_ptr Device manager for the DICE certificate chain.
 */
#define	spdm_certificate_chain_dice_static_init(dice_certs_ptr)	{ \
		.base = SPDM_CERTIFICATE_CHAIN_DICE_API_INIT, \
		.certs = dice_certs_ptr, \
	}


#endif	/* SPDM_CERTIFICATE_CHAIN_DICE_STATIC_H_ */
