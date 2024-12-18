// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECDSA_H_
#define ECDSA_H_

#include <stddef.h>
#include <stdint.h>
#include "crypto/ecc.h"
#include "crypto/ecc_hw.h"
#include "crypto/hash.h"
#include "crypto/rng.h"
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


int ecdsa_deterministic_k_drbg_instantiate (const struct hash_engine *hash,
	enum hmac_hash hmac_algo, const uint8_t *message_digest, size_t digest_length,
	const uint8_t *priv_key, size_t key_length,	struct ecdsa_deterministic_k_drbg *drbg);
int ecdsa_deterministic_k_drbg_generate (const struct hash_engine *hash,
	struct ecdsa_deterministic_k_drbg *drbg, uint8_t *k, size_t k_length);
void ecdsa_deterministic_k_drbg_clear (struct ecdsa_deterministic_k_drbg *drbg);

/* These verification functions are just wrappers around the common digital signature verification
 * routines, leveraging an ephemeral signature_verification_ecc instance.  In most situations,
 * directly interacting with the underlying signature verification calls with a statically allocated
 * instance should be preferred. */
int ecdsa_verify_message (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *message, size_t msg_length, const uint8_t *pub_key,
	size_t key_length, const uint8_t *signature, size_t sig_length);
int ecdsa_verify_hash (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *pub_key, size_t key_length, const uint8_t *signature,
	size_t sig_length);
int ecdsa_verify_hash_and_finish (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *pub_key, size_t key_length, const uint8_t *signature,
	size_t sig_length);

int ecdsa_ecc_hw_sign_message (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct rng_engine *rng, const uint8_t *priv_key,
	size_t key_length, const uint8_t *message, size_t msg_length,
	struct ecc_ecdsa_signature *signature);
int ecdsa_ecc_hw_sign_hash (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct rng_engine *rng, const uint8_t *priv_key,
	size_t key_length, struct ecc_ecdsa_signature *signature);
int ecdsa_ecc_hw_sign_hash_and_finish (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct rng_engine *rng, const uint8_t *priv_key,
	size_t key_length, struct ecc_ecdsa_signature *signature);

int ecdsa_ecc_hw_verify_message (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *message, size_t msg_length,
	const struct ecc_point_public_key *pub_key, const struct ecc_ecdsa_signature *signature);
int ecdsa_ecc_hw_verify_hash (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct ecc_point_public_key *pub_key,
	const struct ecc_ecdsa_signature *signature);
int ecdsa_ecc_hw_verify_hash_and_finish (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash,	enum hash_type hash_algo,
	const struct ecc_point_public_key *pub_key,	const struct ecc_ecdsa_signature *signature);


#define	ECDSA_ERROR(code)		ROT_ERROR (ROT_MODULE_ECDSA, code)

/**
 * Error codes that can be generated during ECDSA processing.
 */
enum {
	ECDSA_INVALID_ARGUMENT = ECDSA_ERROR (0x00),				/**< Input parameter is null or not valid. */
	ECDSA_NO_MEMORY = ECDSA_ERROR (0x01),						/**< Memory allocation failed. */
	ECDSA_P256_SIGN_SELF_TEST_FAILED = ECDSA_ERROR (0x02),		/**< Failed a self-test for ECDSA sign for the P-256 curve. */
	ECDSA_P384_SIGN_SELF_TEST_FAILED = ECDSA_ERROR (0x03),		/**< Failed a self-test for ECDSA sign for the P-384 curve. */
	ECDSA_P521_SIGN_SELF_TEST_FAILED = ECDSA_ERROR (0x04),		/**< Failed a self-test for ECDSA sign for the P-521 curve. */
	ECDSA_P256_VERIFY_SELF_TEST_FAILED = ECDSA_ERROR (0x05),	/**< Failed a self-test for ECDSA verify for the P-256 curve. */
	ECDSA_P384_VERIFY_SELF_TEST_FAILED = ECDSA_ERROR (0x06),	/**< Failed a self-test for ECDSA verify for the P-384 curve. */
	ECDSA_P521_VERIFY_SELF_TEST_FAILED = ECDSA_ERROR (0x07),	/**< Failed a self-test for ECDSA verify for the P-521 curve. */
	ECDSA_UNSUPPORTED_SELF_TEST = ECDSA_ERROR (0x08),			/**< The curve or hash algorithm is not supported. */
};


#endif	/* ECDSA_H_ */
