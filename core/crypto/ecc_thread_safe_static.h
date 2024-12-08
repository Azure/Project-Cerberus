// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_THREAD_SAFE_STATIC_H_
#define ECC_THREAD_SAFE_STATIC_H_

#include "crypto/ecc_thread_safe.h"


/* Internal functions declared to allow for static initialization. */
int ecc_thread_safe_init_key_pair (const struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
int ecc_thread_safe_init_public_key (const struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_public_key *pub_key);
int ecc_thread_safe_generate_derived_key_pair (const struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
int ecc_thread_safe_generate_key_pair (const struct ecc_engine *engine, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
void ecc_thread_safe_release_key_pair (const struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
int ecc_thread_safe_get_signature_max_length (const struct ecc_engine *engine,
	const struct ecc_private_key *key);
int ecc_thread_safe_get_private_key_der (const struct ecc_engine *engine,
	const struct ecc_private_key *key, uint8_t **der, size_t *length);
int ecc_thread_safe_get_public_key_der (const struct ecc_engine *engine,
	const struct ecc_public_key *key, uint8_t **der, size_t *length);
int ecc_thread_safe_sign (const struct ecc_engine *engine, const struct ecc_private_key *key,
	const uint8_t *digest, size_t length, const struct rng_engine *rng, uint8_t *signature,
	size_t sig_length);
int ecc_thread_safe_verify (const struct ecc_engine *engine, const struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length);
int ecc_thread_safe_get_shared_secret_max_length (const struct ecc_engine *engine,
	const struct ecc_private_key *key);
int ecc_thread_safe_compute_shared_secret (const struct ecc_engine *engine,
	const struct ecc_private_key *priv_key, const struct ecc_public_key *pub_key, uint8_t *secret,
	size_t length);


/**
 * Constant initializer for key generation APIs.
 */
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
#define	ECC_THREAD_SAFE_GENERATE_API \
	.generate_derived_key_pair = ecc_thread_safe_generate_derived_key_pair, \
	.generate_key_pair = ecc_thread_safe_generate_key_pair,

#define	ECC_THREAD_SAFE_DER_API \
	.get_private_key_der = ecc_thread_safe_get_private_key_der, \
	.get_public_key_der = ecc_thread_safe_get_public_key_der,
#else
#define	ECC_THREAD_SAFE_GENERATE_API
#define	ECC_THREAD_SAFE_DER_API
#endif

/**
 * Constant initializer for ECDH APIs.
 */
#ifdef ECC_ENABLE_ECDH
#define	ECC_THREAD_SAFE_ECDH_API \
	.get_shared_secret_max_length = ecc_thread_safe_get_shared_secret_max_length, \
	.compute_shared_secret = ecc_thread_safe_compute_shared_secret,
#else
#define	ECC_THREAD_SAFE_ECDH_API
#endif

/**
 * Constant initializer for the ECC API.
 */
#define	ECC_THREAD_SAFE_API_INIT  { \
		.init_key_pair = ecc_thread_safe_init_key_pair, \
		.init_public_key = ecc_thread_safe_init_public_key, \
		ECC_THREAD_SAFE_GENERATE_API \
		.release_key_pair = ecc_thread_safe_release_key_pair, \
		.get_signature_max_length = ecc_thread_safe_get_signature_max_length, \
		ECC_THREAD_SAFE_DER_API \
		.sign = ecc_thread_safe_sign, \
		.verify = ecc_thread_safe_verify, \
		ECC_THREAD_SAFE_ECDH_API \
	}


/**
 * Initialize a static thread-safe wrapper for an ECC engine.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the thread-safe engine.
 * @param target_ptr The target engine that will be used to execute operations.
 */
#define	ecc_thread_safe_static_init(state_ptr, target_ptr)	{ \
		.base = ECC_THREAD_SAFE_API_INIT, \
		.state = state_ptr, \
		.engine = target_ptr, \
	}


#endif	/* ECC_THREAD_SAFE_STATIC_H_ */
