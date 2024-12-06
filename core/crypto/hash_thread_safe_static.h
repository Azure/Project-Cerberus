// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#ifndef HASH_THREAD_SAFE_STATIC_H_
#define HASH_THREAD_SAFE_STATIC_H_

#include "hash_thread_safe.h"


/* Internal functions declared to allow for static initialization. */
int hash_thread_safe_calculate_sha1 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);
int hash_thread_safe_start_sha1 (const struct hash_engine *engine);
int hash_thread_safe_calculate_sha256 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);
int hash_thread_safe_start_sha256 (const struct hash_engine *engine);
int hash_thread_safe_calculate_sha384 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);
int hash_thread_safe_start_sha384 (const struct hash_engine *engine);
int hash_thread_safe_calculate_sha512 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length);
int hash_thread_safe_start_sha512 (const struct hash_engine *engine);
int hash_thread_safe_update (const struct hash_engine *engine, const uint8_t *data, size_t length);
int hash_thread_safe_get_hash (const struct hash_engine *engine, uint8_t *hash, size_t hash_length);
int hash_thread_safe_finish (const struct hash_engine *engine, uint8_t *hash, size_t hash_length);
void hash_thread_safe_cancel (const struct hash_engine *engine);


/**
 * Constant initializer for SHA1 APIs.
 */
#ifdef HASH_ENABLE_SHA1
#define	HASH_THREAD_SAFE_SHA1   \
	.calculate_sha1 = hash_thread_safe_calculate_sha1, \
	.start_sha1 = hash_thread_safe_start_sha1,
#else
#define	HASH_THREAD_SAFE_SHA1
#endif

/**
 * Constant initializer for SHA-256 APIs.
 */
#define	HASH_THREAD_SAFE_SHA256   \
	.calculate_sha256 = hash_thread_safe_calculate_sha256, \
	.start_sha256 = hash_thread_safe_start_sha256,

/**
 * Constant initializer for SHA-384 APIs.
 */
#ifdef HASH_ENABLE_SHA384
#define	HASH_THREAD_SAFE_SHA384 \
	.calculate_sha384 = hash_thread_safe_calculate_sha384, \
	.start_sha384 = hash_thread_safe_start_sha384,
#else
#define	HASH_THREAD_SAFE_SHA384
#endif

/**
 * Constant initializer for SHA-512 APIs.
 */
#ifdef HASH_ENABLE_SHA512
#define	HASH_THREAD_SAFE_SHA512 \
	.calculate_sha512 = hash_thread_safe_calculate_sha512, \
	.start_sha512 = hash_thread_safe_start_sha512,
#else
#define	HASH_THREAD_SAFE_SHA512
#endif

/**
 * Constant initializer for the hash API.
 */
#define	HASH_THREAD_SAFE_API_INIT  { \
		HASH_THREAD_SAFE_SHA1 \
		HASH_THREAD_SAFE_SHA256 \
		HASH_THREAD_SAFE_SHA384 \
		HASH_THREAD_SAFE_SHA512 \
		.update = hash_thread_safe_update, \
		.get_hash = hash_thread_safe_get_hash, \
		.finish = hash_thread_safe_finish, \
		.cancel = hash_thread_safe_cancel, \
	}


/**
 * Initialize a static thread-safe wrapper for a hash engine.
 *
 * There is no validation done on the arguments.
 *
 * @param state_ptr Variable context for the thread-safe engine.
 * @param target_ptr The target engine that will be used to execute operations.
 */
#define	hash_thread_safe_static_init(state_ptr, target_ptr)	{ \
		.base = HASH_THREAD_SAFE_API_INIT, \
		.state = state_ptr, \
		.engine = target_ptr, \
	}


#endif	/* HASH_THREAD_SAFE_STATIC_H_ */
