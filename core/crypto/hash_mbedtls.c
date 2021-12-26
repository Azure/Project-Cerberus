// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "hash_mbedtls.h"


/**
 * Free the active hash context.
 *
 * @param engine The hash engine whose context should be freed.
 */
static void hash_mbedtls_free_context (struct hash_engine_mbedtls *engine)
{
	switch (engine->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			mbedtls_sha1_free (&engine->context.sha1);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			mbedtls_sha256_free (&engine->context.sha256);
			break;

#if defined HASH_ENABLE_SHA384 || defined HASH_ENABLE_SHA512
		case HASH_ACTIVE_SHA384:
		case HASH_ACTIVE_SHA512:
			mbedtls_sha512_free (&engine->context.sha512);
			break;
#endif
	}

	engine->active = HASH_ACTIVE_NONE;
}

#ifdef HASH_ENABLE_SHA1
static int hash_mbedtls_calculate_sha1 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA1_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	return mbedtls_sha1_ret (data, length, hash);
}

static int hash_mbedtls_start_sha1 (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;
	int status;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	mbedtls_sha1_init (&mbedtls->context.sha1);
	status = mbedtls_sha1_starts_ret (&mbedtls->context.sha1);
	if (status != 0) {
		return status;
	}

	mbedtls->active = HASH_ACTIVE_SHA1;
	return 0;
}
#endif

static int hash_mbedtls_calculate_sha256 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	return mbedtls_sha256_ret (data, length, hash, 0);
}

static int hash_mbedtls_start_sha256 (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;
	int status;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	mbedtls_sha256_init (&mbedtls->context.sha256);
	status = mbedtls_sha256_starts_ret (&mbedtls->context.sha256, 0);
	if (status != 0) {
		return status;
	}

	mbedtls->active = HASH_ACTIVE_SHA256;
	return 0;
}

#ifdef HASH_ENABLE_SHA384
static int hash_mbedtls_calculate_sha384 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA384_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	return mbedtls_sha512_ret (data, length, hash, 1);
}

static int hash_mbedtls_start_sha384 (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;
	int status;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	mbedtls_sha512_init (&mbedtls->context.sha512);
	status = mbedtls_sha512_starts_ret (&mbedtls->context.sha512, 1);
	if (status != 0) {
		return status;
	}

	mbedtls->active = HASH_ACTIVE_SHA384;
	return 0;
}
#endif

#ifdef HASH_ENABLE_SHA512
static int hash_mbedtls_calculate_sha512 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA512_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	return mbedtls_sha512_ret (data, length, hash, 0);
}

static int hash_mbedtls_start_sha512 (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;
	int status;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (mbedtls->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	mbedtls_sha512_init (&mbedtls->context.sha512);
	status = mbedtls_sha512_starts_ret (&mbedtls->context.sha512, 0);
	if (status != 0) {
		return status;
	}

	mbedtls->active = HASH_ACTIVE_SHA512;
	return 0;
}
#endif

static int hash_mbedtls_update (struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || ((data == NULL) && (length != 0))) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (mbedtls->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			status = mbedtls_sha1_update_ret (&mbedtls->context.sha1, data, length);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			status = mbedtls_sha256_update_ret (&mbedtls->context.sha256, data, length);
			break;

#if defined HASH_ENABLE_SHA384 || defined HASH_ENABLE_SHA512
		case HASH_ACTIVE_SHA384:
		case HASH_ACTIVE_SHA512:
			status = mbedtls_sha512_update_ret (&mbedtls->context.sha512, data, length);
			break;
#endif

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	return status;
}

static int hash_mbedtls_finish (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;
	int status;

	if ((mbedtls == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (mbedtls->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			if (hash_length < SHA1_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			status = mbedtls_sha1_finish_ret (&mbedtls->context.sha1, hash);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			if (hash_length < SHA256_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			status = mbedtls_sha256_finish_ret (&mbedtls->context.sha256, hash);
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_ACTIVE_SHA384:
			if (hash_length < SHA384_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			status = mbedtls_sha512_finish_ret (&mbedtls->context.sha512, hash);
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_ACTIVE_SHA512:
			if (hash_length < SHA512_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			status = mbedtls_sha512_finish_ret (&mbedtls->context.sha512, hash);
			break;
#endif

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	if (status == 0) {
		hash_mbedtls_free_context (mbedtls);
	}
	return status;
}

static void hash_mbedtls_cancel (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if (mbedtls) {
		hash_mbedtls_free_context (mbedtls);
	}
}

/**
 * Initialize an mbedTLS hash engine.
 *
 * @param engine The hash engine to initialize.
 *
 * @return 0 if the hash engine was successfully initialized or an error code.
 */
int hash_mbedtls_init (struct hash_engine_mbedtls *engine)
{
	if (engine == NULL) {
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
	engine->base.update = hash_mbedtls_update;
	engine->base.finish = hash_mbedtls_finish;
	engine->base.cancel = hash_mbedtls_cancel;

	engine->active = HASH_ACTIVE_NONE;

	return 0;
}

/**
 * Release the resources used by an mbedTLS hash engine.
 *
 * @param engine The hash engine to release.
 */
void hash_mbedtls_release (struct hash_engine_mbedtls *engine)
{
	if (engine != NULL) {
		hash_mbedtls_free_context (engine);
	}
}
