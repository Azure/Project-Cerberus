// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "hash_riot.h"


#ifdef HASH_ENABLE_SHA1
static int hash_riot_calculate_sha1 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_riot *riot = (struct hash_engine_riot*) engine;

	if ((riot == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (riot->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA1_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	RIOT_SHA1_Block (data, length, hash);

	return 0;
}

static int hash_riot_start_sha1 (struct hash_engine *engine)
{
	struct hash_engine_riot *riot = (struct hash_engine_riot*) engine;

	if (riot == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (riot->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	RIOT_SHA1_Init (&riot->context.sha1);
	riot->active = HASH_ACTIVE_SHA1;

	return 0;
}
#endif

static int hash_riot_calculate_sha256 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_riot *riot = (struct hash_engine_riot*) engine;

	if ((riot == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (riot->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	RIOT_SHA256_Block (data, length, hash);

	return 0;
}

static int hash_riot_start_sha256 (struct hash_engine *engine)
{
	struct hash_engine_riot *riot = (struct hash_engine_riot*) engine;

	if (riot == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (riot->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	RIOT_SHA256_Init (&riot->context.sha256);
	riot->active = HASH_ACTIVE_SHA256;

	return 0;
}

#ifdef HASH_ENABLE_SHA384
static int hash_riot_calculate_sha384 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	return HASH_ENGINE_UNSUPPORTED_HASH;
}

static int hash_riot_start_sha384 (struct hash_engine *engine)
{
	return HASH_ENGINE_UNSUPPORTED_HASH;
}
#endif

#ifdef HASH_ENABLE_SHA512
static int hash_riot_calculate_sha512 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	return HASH_ENGINE_UNSUPPORTED_HASH;
}

static int hash_riot_start_sha512 (struct hash_engine *engine)
{
	return HASH_ENGINE_UNSUPPORTED_HASH;
}
#endif

static int hash_riot_update (struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_engine_riot *riot = (struct hash_engine_riot*) engine;

	if ((riot == NULL) || ((data == NULL) && (length != 0))) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (riot->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			RIOT_SHA1_Update (&riot->context.sha1, data, length);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			RIOT_SHA256_Update (&riot->context.sha256, data, length);
			break;

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	return 0;
}

static int hash_riot_finish (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_riot *riot = (struct hash_engine_riot*) engine;

	if ((riot == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (riot->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			if (hash_length < SHA1_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			RIOT_SHA1_Final (&riot->context.sha1, hash);
			break;
#endif

		case HASH_ACTIVE_SHA256:
			if (hash_length < SHA256_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}

			RIOT_SHA256_Final (&riot->context.sha256, hash);
			break;

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	riot->active = HASH_ACTIVE_NONE;
	return 0;
}

static void hash_riot_cancel (struct hash_engine *engine)
{
	struct hash_engine_riot *riot = (struct hash_engine_riot*) engine;

	if (riot) {
		riot->active = HASH_ACTIVE_NONE;
	}
}

/**
 * Initialize a riot hash engine.
 *
 * @param engine The hash engine to initialize.
 *
 * @return 0 if the hash engine was successfully initialized or an error code.
 */
int hash_riot_init (struct hash_engine_riot *engine)
{
	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct hash_engine_riot));

#ifdef HASH_ENABLE_SHA1
	engine->base.calculate_sha1 = hash_riot_calculate_sha1;
	engine->base.start_sha1 = hash_riot_start_sha1;
#endif
	engine->base.calculate_sha256 = hash_riot_calculate_sha256;
	engine->base.start_sha256 = hash_riot_start_sha256;
#ifdef HASH_ENABLE_SHA384
	engine->base.calculate_sha384 = hash_riot_calculate_sha384;
	engine->base.start_sha384 = hash_riot_start_sha384;
#endif
#ifdef HASH_ENABLE_SHA512
	engine->base.calculate_sha512 = hash_riot_calculate_sha512;
	engine->base.start_sha512 = hash_riot_start_sha512;
#endif
	engine->base.update = hash_riot_update;
	engine->base.finish = hash_riot_finish;
	engine->base.cancel = hash_riot_cancel;

	engine->active = HASH_ACTIVE_NONE;

	return 0;
}

/**
 * Release the resources used by a riot hash engine.
 *
 * @param engine The hash engine to release.
 */
void hash_riot_release (struct hash_engine_riot *engine)
{

}
