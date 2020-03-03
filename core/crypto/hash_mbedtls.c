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
	}

	engine->active = HASH_ACTIVE_NONE;
}

#ifdef HASH_ENABLE_SHA1
static int hash_mbedtls_calculate_sha1 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (data == NULL) || (hash == NULL) || (length == 0)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA1_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	mbedtls_sha1 (data, length, hash);

	return 0;
}

static int hash_mbedtls_start_sha1 (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	hash_mbedtls_free_context (mbedtls);

	mbedtls_sha1_init (&mbedtls->context.sha1);
	mbedtls_sha1_starts (&mbedtls->context.sha1);
	mbedtls->active = HASH_ACTIVE_SHA1;

	return 0;
}
#endif

static int hash_mbedtls_calculate_sha256 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (data == NULL) || (hash == NULL) || (length == 0)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	mbedtls_sha256 (data, length, hash, 0);

	return 0;
}

static int hash_mbedtls_start_sha256 (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if (mbedtls == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	hash_mbedtls_free_context (mbedtls);

	mbedtls_sha256_init (&mbedtls->context.sha256);
	mbedtls_sha256_starts (&mbedtls->context.sha256, 0);
	mbedtls->active = HASH_ACTIVE_SHA256;

	return 0;
}

static int hash_mbedtls_update (struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (data == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (mbedtls->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			mbedtls_sha1_update (&mbedtls->context.sha1, data, length);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			mbedtls_sha256_update (&mbedtls->context.sha256, data, length);
			break;

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	return 0;
}

static int hash_mbedtls_finish (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if ((mbedtls == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (mbedtls->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			if (hash_length < SHA1_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			mbedtls_sha1_finish (&mbedtls->context.sha1, hash);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			if (hash_length < SHA256_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			mbedtls_sha256_finish (&mbedtls->context.sha256, hash);
			break;

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	mbedtls->active = HASH_ACTIVE_NONE;
	return 0;
}

static void hash_mbedtls_cancel (struct hash_engine *engine)
{
	struct hash_engine_mbedtls *mbedtls = (struct hash_engine_mbedtls*) engine;

	if (mbedtls) {
		mbedtls->active = HASH_ACTIVE_NONE;
	}
}

/**
 * Initialize an mbed TLS hash engine.
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
	engine->base.update = hash_mbedtls_update;
	engine->base.finish = hash_mbedtls_finish;
	engine->base.cancel = hash_mbedtls_cancel;

	return 0;
}

/**
 * Release the resources used by an mbed TLS hash engine.
 *
 * @param engine The hash engine to release.
 */
void hash_mbedtls_release (struct hash_engine_mbedtls *engine)
{
	if (engine != NULL) {
		hash_mbedtls_free_context (engine);
	}
}
