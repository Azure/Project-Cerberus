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


int ecdsa_deterministic_k_drbg_instantiate (struct ecdsa_deterministic_k_drbg *drbg,
	const struct hash_engine *hash, enum hmac_hash hmac_algo, const uint8_t *message_digest,
	size_t digest_length, const uint8_t *priv_key, size_t key_length);
int ecdsa_deterministic_k_drbg_generate (struct ecdsa_deterministic_k_drbg *drbg,
	const struct hash_engine *hash, uint8_t *k, size_t k_length);
void ecdsa_deterministic_k_drbg_clear (struct ecdsa_deterministic_k_drbg *drbg);

#ifdef ECDSA_ENABLE_FIPS_CMVP_TESTING
/* Flags for PCT fault-injection during key generation for FIPS CMVP certification tests. */
extern bool ecdsa_fail_pct;
extern bool ecdsa_hw_fail_pct;
#endif

int ecdsa_generate_random_key (const struct ecc_engine *ecc, const struct hash_engine *hash,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
int ecdsa_pairwise_consistency_test (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct ecc_private_key *priv_key,
	const struct ecc_public_key *pub_key);

int ecdsa_ecc_hw_generate_random_key (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	size_t key_length, struct ecc_raw_private_key *priv_key, struct ecc_point_public_key *pub_key);
int ecdsa_ecc_hw_pairwise_consistency_test (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash, enum hash_type hash_algo, const uint8_t *priv_key,
	size_t key_length, const struct ecc_point_public_key *pub_key);

int ecdsa_sign_message (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct rng_engine *rng, const uint8_t *priv_key,
	size_t key_length, const uint8_t *message, size_t msg_length, uint8_t *signature,
	size_t sig_length);
int ecdsa_sign_hash (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length, uint8_t *signature,
	size_t sig_length);
int ecdsa_sign_hash_and_finish (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length, uint8_t *signature,
	size_t sig_length);

int ecdsa_sign_message_with_key (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct rng_engine *rng, const struct ecc_private_key *priv_key,
	const uint8_t *message, size_t msg_length, uint8_t *signature, size_t sig_length);
int ecdsa_sign_hash_with_key (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const struct rng_engine *rng, const struct ecc_private_key *priv_key, uint8_t *signature,
	size_t sig_length);
int ecdsa_sign_hash_and_finish_with_key (const struct ecc_engine *ecc,
	const struct hash_engine *hash, const struct rng_engine *rng,
	const struct ecc_private_key *priv_key, uint8_t *signature, size_t sig_length);

/* These verification functions are just wrappers around the common digital signature verification
 * routines, leveraging an ephemeral signature_verification_ecc instance.  In most situations,
 * directly interacting with the underlying signature verification calls with a statically allocated
 * instance should be preferred. */
int ecdsa_verify_message (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *message, size_t msg_length, const uint8_t *pub_key,
	size_t key_length, const uint8_t *signature, size_t sig_length);
int ecdsa_verify_hash (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const uint8_t *pub_key, size_t key_length, const uint8_t *signature, size_t sig_length);
int ecdsa_verify_hash_and_finish (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const uint8_t *pub_key, size_t key_length, const uint8_t *signature, size_t sig_length);

int ecdsa_verify_message_with_key (const struct ecc_engine *ecc, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *message, size_t msg_length,
	const struct ecc_public_key *pub_key, const uint8_t *signature, size_t sig_length);
int ecdsa_verify_hash_with_key (const struct ecc_engine *ecc, const struct hash_engine *hash,
	const struct ecc_public_key *pub_key, const uint8_t *signature, size_t sig_length);
int ecdsa_verify_hash_and_finish_with_key (const struct ecc_engine *ecc,
	const struct hash_engine *hash, const struct ecc_public_key *pub_key, const uint8_t *signature,
	size_t sig_length);

int ecdsa_ecc_hw_sign_message (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const struct rng_engine *rng, const uint8_t *priv_key,
	size_t key_length, const uint8_t *message, size_t msg_length,
	struct ecc_ecdsa_signature *signature);
int ecdsa_ecc_hw_sign_hash (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length,
	struct ecc_ecdsa_signature *signature);
int ecdsa_ecc_hw_sign_hash_and_finish (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	const struct rng_engine *rng, const uint8_t *priv_key, size_t key_length,
	struct ecc_ecdsa_signature *signature);

int ecdsa_ecc_hw_verify_message (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	enum hash_type hash_algo, const uint8_t *message, size_t msg_length,
	const struct ecc_point_public_key *pub_key, const struct ecc_ecdsa_signature *signature);
int ecdsa_ecc_hw_verify_hash (const struct ecc_hw *ecc_hw, const struct hash_engine *hash,
	const struct ecc_point_public_key *pub_key, const struct ecc_ecdsa_signature *signature);
int ecdsa_ecc_hw_verify_hash_and_finish (const struct ecc_hw *ecc_hw,
	const struct hash_engine *hash, const struct ecc_point_public_key *pub_key,
	const struct ecc_ecdsa_signature *signature);


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
	ECDSA_NO_ACTVE_HASH = ECDSA_ERROR (0x09),					/**< There is no active hash context available to sign. */
	ECDSA_PCT_FAILURE = ECDSA_ERROR (0x0a),						/**< Failed the pairwise consistency test. */
};


#endif	/* ECDSA_H_ */
