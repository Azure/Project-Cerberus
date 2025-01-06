// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "hash_thread_safe.h"


#ifdef HASH_ENABLE_SHA1
int hash_thread_safe_calculate_sha1 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->state->lock);
	status = sha->engine->calculate_sha1 (sha->engine, data, length, hash, hash_length);
	platform_mutex_unlock (&sha->state->lock);

	return status;
}

int hash_thread_safe_start_sha1 (const struct hash_engine *engine)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->state->lock);
	status = sha->engine->start_sha1 (sha->engine);
	if (status != 0) {
		platform_mutex_unlock (&sha->state->lock);
	}

	return status;
}
#endif

int hash_thread_safe_calculate_sha256 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->state->lock);
	status = sha->engine->calculate_sha256 (sha->engine, data, length, hash, hash_length);
	platform_mutex_unlock (&sha->state->lock);

	return status;
}

int hash_thread_safe_start_sha256 (const struct hash_engine *engine)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->state->lock);
	status = sha->engine->start_sha256 (sha->engine);
	if (status != 0) {
		platform_mutex_unlock (&sha->state->lock);
	}

	return status;
}

#ifdef HASH_ENABLE_SHA384
int hash_thread_safe_calculate_sha384 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->state->lock);
	status = sha->engine->calculate_sha384 (sha->engine, data, length, hash, hash_length);
	platform_mutex_unlock (&sha->state->lock);

	return status;
}

int hash_thread_safe_start_sha384 (const struct hash_engine *engine)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->state->lock);
	status = sha->engine->start_sha384 (sha->engine);
	if (status != 0) {
		platform_mutex_unlock (&sha->state->lock);
	}

	return status;
}
#endif

#ifdef HASH_ENABLE_SHA512
int hash_thread_safe_calculate_sha512 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->state->lock);
	status = sha->engine->calculate_sha512 (sha->engine, data, length, hash, hash_length);
	platform_mutex_unlock (&sha->state->lock);

	return status;
}

int hash_thread_safe_start_sha512 (const struct hash_engine *engine)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	platform_mutex_lock (&sha->state->lock);
	status = sha->engine->start_sha512 (sha->engine);
	if (status != 0) {
		platform_mutex_unlock (&sha->state->lock);
	}

	return status;
}
#endif

enum hash_type hash_thread_safe_get_active_algorithm (const struct hash_engine *engine)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;

	if (sha == NULL) {
		return HASH_TYPE_INVALID;
	}

	return sha->engine->get_active_algorithm (sha->engine);
}

int hash_thread_safe_update (const struct hash_engine *engine, const uint8_t *data, size_t length)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	return sha->engine->update (sha->engine, data, length);
}

int hash_thread_safe_get_hash (const struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	status = sha->engine->get_hash (sha->engine, hash, hash_length);

	return status;
}

int hash_thread_safe_finish (const struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;
	int status;

	if (sha == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	status = sha->engine->finish (sha->engine, hash, hash_length);
	if (status == 0) {
		/* Only release the lock if finish is successful.  Unsuccessful calls require retry or
		 * cancel. */
		platform_mutex_unlock (&sha->state->lock);
	}

	return status;
}

void hash_thread_safe_cancel (const struct hash_engine *engine)
{
	const struct hash_engine_thread_safe *sha = (const struct hash_engine_thread_safe*) engine;

	if (sha == NULL) {
		return;
	}

	sha->engine->cancel (sha->engine);
	platform_mutex_unlock (&sha->state->lock);
}

/**
 * Initialize a thread-safe wrapper for a hash engine.
 *
 * @param engine The thread-safe engine to initialize.
 * @param target The target engine that will be used to execute operations.
 *
 * @return 0 if the engine was successfully initialized or an error code.
 */
int hash_thread_safe_init (struct hash_engine_thread_safe *engine,
	struct hash_engine_thread_safe_state *state, const struct hash_engine *target)
{
	if ((engine == NULL) || (state == NULL) || (target == NULL)) {
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
	engine->base.get_active_algorithm = hash_thread_safe_get_active_algorithm;
	engine->base.update = hash_thread_safe_update;
	engine->base.get_hash = hash_thread_safe_get_hash;
	engine->base.finish = hash_thread_safe_finish;
	engine->base.cancel = hash_thread_safe_cancel;

	engine->state = state;
	engine->engine = target;

	return hash_thread_safe_init_state (engine);
}

/**
 * Initialize only the variable state of thread-state hash engine wrapper.  The rest of the instance
 * is assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The hash engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int hash_thread_safe_init_state (const struct hash_engine_thread_safe *engine)
{
	if ((engine == NULL) || (engine->state == NULL) || (engine->engine == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	return platform_mutex_init (&engine->state->lock);
}

/**
 * Release the resources used for a thread-safe hash wrapper.
 *
 * @param engine The thread-safe engine to release.
 */
void hash_thread_safe_release (const struct hash_engine_thread_safe *engine)
{
	if (engine != NULL) {
		platform_mutex_free (&engine->state->lock);
	}
}
