// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECDSA_H_
#define ECDSA_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/hash.h"
#include "status/rot_status.h"


/**
 * Context used to generate deterministic k values for ECDSA signing operations following the
 * algorithm specified in RFC 6979.
 */
struct ecdsa_deterministic_k_drbg {
	enum hmac_hash hmac_algo;			/**< HMAC algorithm used by the DRBG. */
	uint8_t key[HASH_MAX_HASH_LEN];		/**< Current DRBG HMAC key (K). */
	uint8_t value[HASH_MAX_HASH_LEN];	/**< Current DRBG HMAC value (V). */
	bool first;							/**< Flag to indicate if a k has already been generated. */
};


int ecdsa_deterministic_k_drbg_instantiate (struct hash_engine *hash, enum hmac_hash hmac_algo,
	const uint8_t *message_digest, size_t digest_length, const uint8_t *priv_key, size_t key_length,
	struct ecdsa_deterministic_k_drbg *drbg);
int ecdsa_deterministic_k_drbg_generate (struct hash_engine *hash,
	struct ecdsa_deterministic_k_drbg *drbg, uint8_t *k, size_t k_length);
void ecdsa_deterministic_k_drbg_clear (struct ecdsa_deterministic_k_drbg *drbg);


#define	ECDSA_ERROR(code)		ROT_ERROR (ROT_MODULE_ECDSA, code)

/**
 * Error codes that can be generated during ECDSA processing.
 */
enum {
	ECDSA_INVALID_ARGUMENT = ECDSA_ERROR (0x00),	/**< Input parameter is null or not valid. */
	ECDSA_NO_MEMORY = ECDSA_ERROR (0x01),			/**< Memory allocation failed. */
};


#endif	/* ECDSA_H_ */
