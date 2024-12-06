// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_MBEDTLS_STATIC_H_
#define RSA_MBEDTLS_STATIC_H_

#include "rsa_mbedtls.h"


/* Internal functions declared to allow for static initialization. */
int rsa_mbedtls_generate_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	int bits);
int rsa_mbedtls_init_private_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length);
void rsa_mbedtls_release_key (const struct rsa_engine *engine, struct rsa_private_key *key);
int rsa_mbedtls_get_private_key_der (const struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length);
int rsa_mbedtls_decrypt (const struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length);
int rsa_mbedtls_init_public_key (const struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length);
int rsa_mbedtls_get_public_key_der (const struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length);
int rsa_mbedtls_sig_verify (const struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, enum hash_type sig_hash, const uint8_t *match,
	size_t match_length);


/**
 * Constant initializer for private key APIs.
 */
#ifdef RSA_ENABLE_PRIVATE_KEY
#define	RSA_MBEDTLS_PRIVATE_KEY   \
	.generate_key = rsa_mbedtls_generate_key, \
	.init_private_key = rsa_mbedtls_init_private_key, \
	.release_key = rsa_mbedtls_release_key, \
	.get_private_key_der = rsa_mbedtls_get_private_key_der, \
	.decrypt = rsa_mbedtls_decrypt,
#else
#define	RSA_MBEDTLS_PRIVATE_KEY
#endif

/**
 * Constant initializer for DER public key APIs.
 */
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
#define	RSA_MBEDTLS_DER_PUBLIC_KEY \
	.init_public_key = rsa_mbedtls_init_public_key, \
	.get_public_key_der = rsa_mbedtls_get_public_key_der,
#else
#define	RSA_MBEDTLS_DER_PUBLIC_KEY
#endif

/**
 * Constant initializer for the RSA API.
 */
#define	RSA_MBEDTLS_API_INIT  { \
		RSA_MBEDTLS_PRIVATE_KEY \
		RSA_MBEDTLS_DER_PUBLIC_KEY \
		.sig_verify = rsa_mbedtls_sig_verify, \
	}


/**
 * Initialize a static mbedTLS RSA engine.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for RSA operations.
 */
#define	rsa_mbedtls_static_init(state_ptr) { \
		.base = RSA_MBEDTLS_API_INIT, \
		.state = state_ptr, \
	}


#endif	/* RSA_MBEDTLS_STATIC_H_ */
