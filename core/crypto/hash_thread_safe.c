// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "hash_thread_safe.h"


#ifdef HASH_ENABLE_SHA1
static int hash_thread_safe_calculate_sha1 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->lock);
	status = sha->engine->calculate_sha1 (sha->engine, data, length, hash, hash_length);
	platform_mutex_unlock (&sha->lock);

	return status;
}

static int hash_thread_safe_start_sha1 (struct hash_engine *engine)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->lock);
	status = sha->engine->start_sha1 (sha->engine);
	if (status != 0) {
		platform_mutex_unlock (&sha->lock);
	}

	return status;
}
#endif

static int hash_thread_safe_calculate_sha256 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->lock);
	status = sha->engine->calculate_sha256 (sha->engine, data, length, hash, hash_length);
	platform_mutex_unlock (&sha->lock);

	return status;
}

static int hash_thread_safe_start_sha256 (struct hash_engine *engine)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->lock);
	status = sha->engine->start_sha256 (sha->engine);
	if (status != 0) {
		platform_mutex_unlock (&sha->lock);
	}

	return status;
}

#ifdef HASH_ENABLE_SHA384
static int hash_thread_safe_calculate_sha384 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->lock);
	status = sha->engine->calculate_sha384 (sha->engine, data, length, hash, hash_length);
	platform_mutex_unlock (&sha->lock);

	return status;
}

static int hash_thread_safe_start_sha384 (struct hash_engine *engine)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->lock);
	status = sha->engine->start_sha384 (sha->engine);
	if (status != 0) {
		platform_mutex_unlock (&sha->lock);
	}

	return status;
}
#endif

#ifdef HASH_ENABLE_SHA512
static int hash_thread_safe_calculate_sha512 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->lock);
	status = sha->engine->calculate_sha512 (sha->engine, data, length, hash, hash_length);
	platform_mutex_unlock (&sha->lock);

	return status;
}

static int hash_thread_safe_start_sha512 (struct hash_engine *engine)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->lock);
	status = sha->engine->start_sha512 (sha->engine);
	if (status != 0) {
		platform_mutex_unlock (&sha->lock);
	}

	return status;
}
#endif

static int hash_thread_safe_update (struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	return sha->engine->update (sha->engine, data, length);
}

static int hash_thread_safe_finish (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	status = sha->engine->finish (sha->engine, hash, hash_length);
	if (status == 0) {
		/* Only release the lock if finish is successful.  Unsuccessful calls require retry or
		 * cancel. */
		platform_mutex_unlock (&sha->lock);
	}

	return status;
}

static void hash_thread_safe_cancel (struct hash_engine *engine)
{
	struct hash_engine_thread_safe *sha = (struct hash_engine_thread_safe*) engine;

	if (sha == NULL) {
		return;
	}

	sha->engine->cancel (sha->engine);
	platform_mutex_unlock (&sha->lock);
}

/**
 * Initialize a thread-safe wrapper for a hash engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int hash_thread_safe_init (struct hash_engine_thread_safe *engine, struct hash_engine *target)
{
	if ((engine == NULL) || (target == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct hash_engine_thread_safe));

#ifdef HASH_ENABLE_SHA1
	engine->base.calculate_sha1 = hash_thread_safe_calculate_sha1;
	engine->base.start_sha1 = hash_thread_safe_start_sha1;
#endif
	engine->base.calculate_sha256 = hash_thread_safe_calculate_sha256;
	engine->base.start_sha256 = hash_thread_safe_start_sha256;
#ifdef HASH_ENABLE_SHA384
	engine->base.calculate_sha384 = hash_thread_safe_calculate_sha384;
	engine->base.start_sha384 = hash_thread_safe_start_sha384;
#endif
#ifdef HASH_ENABLE_SHA512
	engine->base.calculate_sha512 = hash_thread_safe_calculate_sha512;
	engine->base.start_sha512 = hash_thread_safe_start_sha512;
#endif
	engine->base.update = hash_thread_safe_update;
	engine->base.finish = hash_thread_safe_finish;
	engine->base.cancel = hash_thread_safe_cancel;

	engine->engine = target;

	return platform_mutex_init (&engine->lock);
}

/**
 * Release the resources used for a thread-safe hash wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void hash_thread_safe_release (struct hash_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->lock);
	}
}
