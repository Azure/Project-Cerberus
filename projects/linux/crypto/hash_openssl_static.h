// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_OPENSSL_STATIC_H_
#define HASH_OPENSSL_STATIC_H_

#include "hash_openssl.h"


/* Internal functions declared to allow for static initialization. */
int hash_openssl_calculate_sha1 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);
int hash_openssl_start_sha1 (const struct hash_engine *engine);
int hash_openssl_calculate_sha256 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);
int hash_openssl_start_sha256 (const struct hash_engine *engine);
int hash_openssl_calculate_sha384 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);
int hash_openssl_start_sha384 (const struct hash_engine *engine);
int hash_openssl_calculate_sha512 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);
int hash_openssl_start_sha512 (const struct hash_engine *engine);
int hash_openssl_update (const struct hash_engine *engine, const uint8_t *data, size_t length);
int hash_openssl_get_hash (const struct hash_engine *engine, uint8_t *hash, size_t hash_length);
int hash_openssl_finish (const struct hash_engine *engine, uint8_t *hash, size_t hash_length);
void hash_openssl_cancel (const struct hash_engine *engine);


/**
 * Constant initializer for SHA1 APIs.
 */
#ifdef HASH_ENABLE_SHA1
#define	HASH_OPENSSL_SHA1   \
	.calculate_sha1 = hash_openssl_calculate_sha1, \
	.start_sha1 = hash_openssl_start_sha1,
#else
#define	HASH_OPENSSL_SHA1
#endif

/**
 * Constant initializer for SHA-256 APIs.
 */
#define	HASH_OPENSSL_SHA256   \
	.calculate_sha256 = hash_openssl_calculate_sha256, \
	.start_sha256 = hash_openssl_start_sha256,

/**
 * Constant initializer for SHA-384 APIs.
 */
#ifdef HASH_ENABLE_SHA384
#define	HASH_OPENSSL_SHA384 \
	.calculate_sha384 = hash_openssl_calculate_sha384, \
	.start_sha384 = hash_openssl_start_sha384,
#else
#define	HASH_OPENSSL_SHA384
#endif

/**
 * Constant initializer for SHA-512 APIs.
 */
#ifdef HASH_ENABLE_SHA512
#define	HASH_OPENSSL_SHA512 \
	.calculate_sha512 = hash_openssl_calculate_sha512, \
	.start_sha512 = hash_openssl_start_sha512,
#else
#define	HASH_OPENSSL_SHA512
#endif

/**
 * Constant initializer for the hash API.
 */
#define	HASH_OPENSSL_API_INIT  { \
		HASH_OPENSSL_SHA1 \
		HASH_OPENSSL_SHA256 \
		HASH_OPENSSL_SHA384 \
		HASH_OPENSSL_SHA512 \
		.update = hash_openssl_update, \
		.get_hash = hash_openssl_get_hash, \
		.finish = hash_openssl_finish, \
		.cancel = hash_openssl_cancel, \
	}


/**
 * Initialize a static hash engine using mbedTLS.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the hash engine.
 */
#define	hash_openssl_static_init(state_ptr)	{ \
		.base = HASH_OPENSSL_API_INIT, \
		.state = state_ptr, \
	}


#endif /* HASH_OPENSSL_STATIC_H_ */
