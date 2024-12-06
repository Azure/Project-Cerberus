// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_OPENSSL_STATIC_H_
#define RSA_OPENSSL_STATIC_H_

#include "rsa_openssl.h"


/* Internal functions declared to allow for static initialization. */
int rsa_openssl_generate_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	int bits);
int rsa_openssl_init_private_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length);
void rsa_openssl_release_key (const struct rsa_engine *engine, struct rsa_private_key *key);
int rsa_openssl_get_private_key_der (const struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length);
int rsa_openssl_decrypt (const struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length);
int rsa_openssl_init_public_key (const struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length);
int rsa_openssl_get_public_key_der (const struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length);
int rsa_openssl_sig_verify (const struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, enum hash_type sig_hash, const uint8_t *match,
	size_t match_length);


/**
 * Constant initializer for private key APIs.
 */
#ifdef RSA_ENABLE_PRIVATE_KEY
#define	RSA_OPENSSL_PRIVATE_KEY   \
	.generate_key = rsa_openssl_generate_key, \
	.init_private_key = rsa_openssl_init_private_key, \
	.release_key = rsa_openssl_release_key, \
	.get_private_key_der = rsa_openssl_get_private_key_der, \
	.decrypt = rsa_openssl_decrypt,
#else
#define	RSA_OPENSSL_PRIVATE_KEY
#endif

/**
 * Constant initializer for DER public key APIs.
 */
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
#define	RSA_OPENSSL_DER_PUBLIC_KEY \
	.init_public_key = rsa_openssl_init_public_key, \
	.get_public_key_der = rsa_openssl_get_public_key_der,
#else
#define	RSA_OPENSSL_DER_PUBLIC_KEY
#endif

/**
 * Constant initializer for the RSA API.
 */
#define	RSA_OPENSSL_API_INIT  { \
		RSA_OPENSSL_PRIVATE_KEY \
		RSA_OPENSSL_DER_PUBLIC_KEY \
		.sig_verify = rsa_openssl_sig_verify, \
	}


/**
 * Initialize a static OpenSSL RSA engine.
 */
#define	rsa_openssl_static_init { \
		.base = RSA_OPENSSL_API_INIT, \
	}


#endif /* RSA_OPENSSL_STATIC_H_ */
