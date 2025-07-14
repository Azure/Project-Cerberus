// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef ECC_MBEDTLS_STATIC_H_
#define ECC_MBEDTLS_STATIC_H_

#include "crypto/ecc_mbedtls.h"
#include "crypto/rng_mbedtls.h"


/* Internal functions declared to allow for static initialization. */
int ecc_mbedtls_init_key_pair (const struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
int ecc_mbedtls_init_public_key (const struct ecc_engine *engine, const uint8_t *key,
	size_t key_length, struct ecc_public_key *pub_key);
int ecc_mbedtls_generate_derived_key_pair (const struct ecc_engine *engine, const uint8_t *priv,
	size_t key_length, struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
int ecc_mbedtls_generate_key_pair (const struct ecc_engine *engine, size_t key_length,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
void ecc_mbedtls_release_key_pair (const struct ecc_engine *engine,
	struct ecc_private_key *priv_key, struct ecc_public_key *pub_key);
int ecc_mbedtls_get_signature_max_length (const struct ecc_engine *engine,
	const struct ecc_private_key *key);
int ecc_mbedtls_get_signature_max_verify_length (const struct ecc_engine *engine,
	const struct ecc_public_key *key);
int ecc_mbedtls_get_private_key_der (const struct ecc_engine *engine,
	const struct ecc_private_key *key, uint8_t **der, size_t *length);
int ecc_mbedtls_get_public_key_der (const struct ecc_engine *engine,
	const struct ecc_public_key *key, uint8_t **der, size_t *length);
int ecc_mbedtls_sign (const struct ecc_engine *engine, const struct ecc_private_key *key,
	const uint8_t *digest, size_t length, const struct rng_engine *rng, uint8_t *signature,
	size_t sig_length);
int ecc_mbedtls_verify (const struct ecc_engine *engine, const struct ecc_public_key *key,
	const uint8_t *digest, size_t length, const uint8_t *signature, size_t sig_length);
int ecc_mbedtls_get_shared_secret_max_length (const struct ecc_engine *engine,
	const struct ecc_private_key *key);
int ecc_mbedtls_compute_shared_secret (const struct ecc_engine *engine,
	const struct ecc_private_key *priv_key, const struct ecc_public_key *pub_key, uint8_t *secret,
	size_t length);


/**
 * Constant initializer for key generation APIs.
 */
#ifdef ECC_ENABLE_GENERATE_KEY_PAIR
#define	ECC_MBEDTLS_GENERATE_API \
	.generate_derived_key_pair = ecc_mbedtls_generate_derived_key_pair, \
	.generate_key_pair = ecc_mbedtls_generate_key_pair,

#define	ECC_MBEDTLS_DER_API \
	.get_private_key_der = ecc_mbedtls_get_private_key_der, \
	.get_public_key_der = ecc_mbedtls_get_public_key_der,
#else
#define	ECC_MBEDTLS_GENERATE_API
#define	ECC_MBEDTLS_DER_API
#endif

/**
 * Constant initializer for ECDH APIs.
 */
#ifdef ECC_ENABLE_ECDH
#define	ECC_MBEDTLS_ECDH_API \
	.get_shared_secret_max_length = ecc_mbedtls_get_shared_secret_max_length, \
	.compute_shared_secret = ecc_mbedtls_compute_shared_secret,
#else
#define	ECC_MBEDTLS_ECDH_API
#endif

/**
 * Constant initializer for the ECC API.
 */
#define	ECC_MBEDTLS_API_INIT  { \
		.init_key_pair = ecc_mbedtls_init_key_pair, \
		.init_public_key = ecc_mbedtls_init_public_key, \
		ECC_MBEDTLS_GENERATE_API \
		.release_key_pair = ecc_mbedtls_release_key_pair, \
		.get_signature_max_length = ecc_mbedtls_get_signature_max_length, \
		.get_signature_max_verify_length = ecc_mbedtls_get_signature_max_verify_length, \
		ECC_MBEDTLS_DER_API \
		.sign = ecc_mbedtls_sign, \
		.verify = ecc_mbedtls_verify, \
		ECC_MBEDTLS_ECDH_API \
	}


/**
 * Initialize a static for running ECC operations using mbedTLS.
 *
 * Random number generation will be handled by an internally managed mbedTLS implementation of a
 * software DRBG.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the ECC engine.
 */
#define	ecc_mbedtls_static_init(state_ptr)	{ \
		.base = ECC_MBEDTLS_API_INIT, \
		.state = state_ptr, \
		.rng = &(state_ptr)->ctr_drbg, \
		.f_rng = mbedtls_ctr_drbg_random, \
	}

/**
 * Initialize a static for running ECC operations using mbedTLS.
 *
 * Random number generation will be handled by the provided RNG engine.
 *
 * There is no validation done on the arguments.
 *
 * @note There is no variable state when operating in this mode, so no state structure is required.
 * As such, there is no need to call ecc_mbedtls_init_state() to complete initialization of this
 * instance.
 *
 * @param rng_ptr The source for random numbers during ECC operations.
 */
#define	ecc_mbedtls_static_init_with_external_rng(rng_ptr)	{ \
		.base = ECC_MBEDTLS_API_INIT, \
		.state = NULL, \
		.rng = (void*) rng_ptr, \
		.f_rng = rng_mbedtls_rng_callback, \
	}


#endif	/* ECC_MBEDTLS_STATIC_H_ */
