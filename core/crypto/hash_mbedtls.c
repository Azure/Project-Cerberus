// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "hash_mbedtls.h"
#include "crypto/mbedtls_compat.h"


/**
 * Handle the different function names between mbedTLS version 2 and 3.
 */
#if MBEDTLS_IS_VERSION_3
#define	HASH_MBEDTLS_SHA_FUNCTION(func)	func
#else
#define	HASH_MBEDTLS_SHA_FUNCTION(func)	func ## _ret
#endif


/**
 * Free the active hash context.
 *
 * @param state The hash engine context that should be freed.
 */
static void hash_mbedtls_free_context (struct hash_engine_mbedtls_state *state)
{
	switch (state->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			mbedtls_sha1_free (&state->context.sha1);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			mbedtls_sha256_free (&state->context.sha256);
			break;

#if defined HASH_ENABLE_SHA384 || defined HASH_ENABLE_SHA512
		case HASH_ACTIVE_SHA384:
		case HASH_ACTIVE_SHA512:
			mbedtls_sha512_free (&state->context.sha512);
			break;
#endif
	}

	state->active = HASH_ACTIVE_NONE;
}

#ifdef HASH_ENABLE_SHA1
int hash_mbedtls_calculate_sha1 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->state->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA1_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	return HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha1) (data, length, hash);
}

int hash_mbedtls_start_sha1 (const struct hash_engine *engine)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;
	int status;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->state->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	mbedtls_sha1_init (&mbedtls->state->context.sha1);
	status = HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha1_starts) (&mbedtls->state->context.sha1);
	if (status != 0) {
		return status;
	}

	mbedtls->state->active = HASH_ACTIVE_SHA1;

	return 0;
}
#endif

int hash_mbedtls_calculate_sha256 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->state->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	return HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha256) (data, length, hash, 0);
}

int hash_mbedtls_start_sha256 (const struct hash_engine *engine)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;
	int status;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->state->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	mbedtls_sha256_init (&mbedtls->state->context.sha256);
	status = HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha256_starts) (&mbedtls->state->context.sha256, 0);
	if (status != 0) {
		return status;
	}

	mbedtls->state->active = HASH_ACTIVE_SHA256;

	return 0;
}

#ifdef HASH_ENABLE_SHA384
int hash_mbedtls_calculate_sha384 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->state->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA384_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	return HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha512) (data, length, hash, 1);
}

int hash_mbedtls_start_sha384 (const struct hash_engine *engine)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;
	int status;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->state->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	mbedtls_sha512_init (&mbedtls->state->context.sha512);
	status = HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha512_starts) (&mbedtls->state->context.sha512, 1);
	if (status != 0) {
		return status;
	}

	mbedtls->state->active = HASH_ACTIVE_SHA384;

	return 0;
}
#endif

#ifdef HASH_ENABLE_SHA512
int hash_mbedtls_calculate_sha512 (const struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->state->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA512_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	return HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha512) (data, length, hash, 0);
}

int hash_mbedtls_start_sha512 (const struct hash_engine *engine)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;
	int status;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->state->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	mbedtls_sha512_init (&mbedtls->state->context.sha512);
	status = HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha512_starts) (&mbedtls->state->context.sha512, 0);
	if (status != 0) {
		return status;
	}

	mbedtls->state->active = HASH_ACTIVE_SHA512;

	return 0;
}
#endif

enum hash_type hash_mbedtls_get_active_algorithm (const struct hash_engine *engine)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;

	if (mbedtls == NULL) {
		return HASH_TYPE_INVALID;
	}

	return hash_get_type_from_active (mbedtls->state->active);
}

int hash_mbedtls_update (const struct hash_engine *engine, const uint8_t *data, size_t length)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0))) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (mbedtls->state->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			status = HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha1_update) (&mbedtls->state->context.sha1,
				data, length);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			status =
				HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha256_update) (&mbedtls->state->context.sha256,
				data, length);
			break;

#if defined HASH_ENABLE_SHA384 || defined HASH_ENABLE_SHA512
		case HASH_ACTIVE_SHA384:
		case HASH_ACTIVE_SHA512:
			status =
				HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha512_update) (&mbedtls->state->context.sha512,
				data, length);
			break;
#endif

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	return status;
}

int hash_mbedtls_get_hash (const struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;
	struct hash_engine_mbedtls_state mbedtls_clone;
	int status;

	if ((mbedtls == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	mbedtls_clone.active = mbedtls->state->active;

	switch (mbedtls_clone.active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			if (hash_length < SHA1_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			mbedtls_sha1_init (&mbedtls_clone.context.sha1);
			mbedtls_sha1_clone (&mbedtls_clone.context.sha1, &mbedtls->state->context.sha1);
			status = HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha1_finish) (&mbedtls_clone.context.sha1,
				hash);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			if (hash_length < SHA256_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			mbedtls_sha256_init (&mbedtls_clone.context.sha256);
			mbedtls_sha256_clone (&mbedtls_clone.context.sha256, &mbedtls->state->context.sha256);
			status =
				HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha256_finish) (&mbedtls_clone.context.sha256,
				hash);
			break;

#if defined HASH_ENABLE_SHA384 || defined HASH_ENABLE_SHA512
		case HASH_ACTIVE_SHA384:
		case HASH_ACTIVE_SHA512:
			if (((mbedtls_clone.active == HASH_ACTIVE_SHA512) &&
				(hash_length < SHA512_HASH_LENGTH)) ||
				((mbedtls_clone.active == HASH_ACTIVE_SHA384) &&
				(hash_length < SHA384_HASH_LENGTH))) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			mbedtls_sha512_init (&mbedtls_clone.context.sha512);
			mbedtls_sha512_clone (&mbedtls_clone.context.sha512, &mbedtls->state->context.sha512);
			status =
				HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha512_finish) (&mbedtls_clone.context.sha512,
				hash);
			break;
#endif

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	hash_mbedtls_free_context (&mbedtls_clone);

	return status;
}

int hash_mbedtls_finish (const struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (mbedtls->state->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			if (hash_length < SHA1_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			status = HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha1_finish) (&mbedtls->state->context.sha1,
				hash);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			if (hash_length < SHA256_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			status =
				HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha256_finish) (&mbedtls->state->context.sha256,
				hash);
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_ACTIVE_SHA384:
			if (hash_length < SHA384_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			status =
				HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha512_finish) (&mbedtls->state->context.sha512,
				hash);
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_ACTIVE_SHA512:
			if (hash_length < SHA512_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			status =
				HASH_MBEDTLS_SHA_FUNCTION (mbedtls_sha512_finish) (&mbedtls->state->context.sha512,
				hash);
			break;
#endif

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	if (status == 0) {
		hash_mbedtls_free_context (mbedtls->state);
	}

	return status;
}

void hash_mbedtls_cancel (const struct hash_engine *engine)
{
	const struct hash_engine_mbedtls *mbedtls = (const struct hash_engine_mbedtls*) engine;

	if (mbedtls) {
		hash_mbedtls_free_context (mbedtls->state);
	}
}

/**
 * Initialize an mbedTLS hash engine.
 *
 * @param engine The hash engine to initialize.
 * @param state Variable context for the hash engine.  This must be uninitialized.
 *
 * @return 0 if the hash engine was successfully initialized or an error code.
 */
int hash_mbedtls_init (struct hash_engine_mbedtls *engine, struct hash_engine_mbedtls_state *state)
{
	if ((engine == NULL) || (state == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct hash_engine_mbedtls));

#ifdef HASH_ENABLE_SHA1
	engine->base.calculate_sha1 = hash_mbedtls_calculate_sha1;
	engine->base.start_sha1 = hash_mbedtls_start_sha1;
#endif
	engine->base.calculate_sha256 = hash_mbedtls_calculate_sha256;
	engine->base.start_sha256 = hash_mbedtls_start_sha256;
#ifdef HASH_ENABLE_SHA384
	engine->base.calculate_sha384 = hash_mbedtls_calculate_sha384;
	engine->base.start_sha384 = hash_mbedtls_start_sha384;
#endif
#ifdef HASH_ENABLE_SHA512
	engine->base.calculate_sha512 = hash_mbedtls_calculate_sha512;
	engine->base.start_sha512 = hash_mbedtls_start_sha512;
#endif
	engine->base.get_active_algorithm = hash_mbedtls_get_active_algorithm;
	engine->base.update = hash_mbedtls_update;
	engine->base.get_hash = hash_mbedtls_get_hash;
	engine->base.finish = hash_mbedtls_finish;
	engine->base.cancel = hash_mbedtls_cancel;

	engine->state = state;

	return hash_mbedtls_init_state (engine);
}

/**
 * Initialize only the variable state of an mbedTLS hash engine.  The rest of the instance is
 * assumed to already have been initialized.
 *
 * This would generally be used with a statically initialized instance.
 *
 * @param engine The hash engine that contains the state to initialize.
 *
 * @return 0 if the state was successfully initialized or an error code.
 */
int hash_mbedtls_init_state (const struct hash_engine_mbedtls *engine)
{
	if ((engine == NULL) || (engine->state == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine->state, 0, sizeof (*engine->state));

	engine->state->active = HASH_ACTIVE_NONE;

	return 0;
}

/**
 * Release the resources used by an mbedTLS hash engine.
 *
 * @param engine The hash engine to release.
 */
void hash_mbedtls_release (const struct hash_engine_mbedtls *engine)
{
	if (engine != NULL) {
		hash_mbedtls_free_context (engine->state);
	}
}
