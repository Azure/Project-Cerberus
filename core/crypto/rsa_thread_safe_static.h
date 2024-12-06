// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef RSA_THREAD_SAFE_STATIC_H_
#define RSA_THREAD_SAFE_STATIC_H_

#include "rsa_thread_safe.h"


/* Internal functions declared to allow for static initialization. */
int rsa_thread_safe_generate_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	int bits);
int rsa_thread_safe_init_private_key (const struct rsa_engine *engine, struct rsa_private_key *key,
	const uint8_t *der, size_t length);
void rsa_thread_safe_release_key (const struct rsa_engine *engine, struct rsa_private_key *key);
int rsa_thread_safe_get_private_key_der (const struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length);
int rsa_thread_safe_decrypt (const struct rsa_engine *engine, const struct rsa_private_key *key,
	const uint8_t *encrypted, size_t in_length, const uint8_t *label, size_t label_length,
	enum hash_type pad_hash, uint8_t *decrypted, size_t out_length);
int rsa_thread_safe_init_public_key (const struct rsa_engine *engine, struct rsa_public_key *key,
	const uint8_t *der, size_t length);
int rsa_thread_safe_get_public_key_der (const struct rsa_engine *engine,
	const struct rsa_private_key *key, uint8_t **der, size_t *length);
int rsa_thread_safe_sig_verify (const struct rsa_engine *engine, const struct rsa_public_key *key,
	const uint8_t *signature, size_t sig_length, enum hash_type sig_hash, const uint8_t *match,
	size_t match_length);


/**
 * Constant initializer for private key APIs.
 */
#ifdef RSA_ENABLE_PRIVATE_KEY
#define	RSA_THREAD_SAFE_PRIVATE_KEY   \
	.generate_key = rsa_thread_safe_generate_key, \
	.init_private_key = rsa_thread_safe_init_private_key, \
	.release_key = rsa_thread_safe_release_key, \
	.get_private_key_der = rsa_thread_safe_get_private_key_der, \
	.decrypt = rsa_thread_safe_decrypt,
#else
#define	RSA_THREAD_SAFE_PRIVATE_KEY
#endif

/**
 * Constant initializer for DER public key APIs.
 */
#ifdef RSA_ENABLE_DER_PUBLIC_KEY
#define	RSA_THREAD_SAFE_DER_PUBLIC_KEY \
	.init_public_key = rsa_thread_safe_init_public_key, \
	.get_public_key_der = rsa_thread_safe_get_public_key_der,
#else
#define	RSA_THREAD_SAFE_DER_PUBLIC_KEY
#endif

/**
 * Constant initializer for the RSA API.
 */
#define	RSA_THREAD_SAFE_API_INIT  { \
		RSA_THREAD_SAFE_PRIVATE_KEY \
		RSA_THREAD_SAFE_DER_PUBLIC_KEY \
		.sig_verify = rsa_thread_safe_sig_verify, \
	}


/**
 * Initialize a static thread-safe wrapper for an RSA engine.
 *
 * There is no validation done on the arguments.
 *
 * @param state Variable context for the thread-safe wrapper.
 * @param target The target engine that will be used to execute operations.
 */
#define	rsa_thread_safe_static_init(state_ptr, target_ptr) { \
		.base = RSA_THREAD_SAFE_API_INIT, \
		.state = state_ptr, \
		.engine = target_ptr, \
	}


#endif	/* RSA_THREAD_SAFE_STATIC_H_ */
