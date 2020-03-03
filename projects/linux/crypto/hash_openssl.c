// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include "hash_openssl.h"


#ifdef HASH_ENABLE_SHA1
static int hash_openssl_calculate_sha1 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	if ((engine == NULL) || (data == NULL) || (hash == NULL) || (length == 0 )) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA1_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	SHA1 (data, length, hash);
	return 0;
}

static int hash_openssl_start_sha1 (struct hash_engine *engine)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if (openssl == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (SHA1_Init (&openssl->sha1) == 1) {
		openssl->active = HASH_ACTIVE_SHA1;
		return 0;
	}
	else {
		return HASH_ENGINE_START_SHA1_FAILED;
	}
}
#endif

static int hash_openssl_calculate_sha256 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	if ((engine == NULL) || (data == NULL) || (hash == NULL) || (length == 0 )) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (hash_length < SHA256_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	SHA256 (data, length, hash);
	return 0;
}

static int hash_openssl_start_sha256 (struct hash_engine *engine)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if (openssl == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (SHA256_Init (&openssl->sha256) == 1) {
		openssl->active = HASH_ACTIVE_SHA256;
		return 0;
	}
	else {
		return HASH_ENGINE_START_SHA256_FAILED;
	}
}

static int hash_openssl_update (struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;
	int status;

	if ((openssl == NULL) || (data == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (openssl->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			if (SHA1_Update (&openssl->sha1, data, length) == 1) {
				status = 0;
			}
			else {
				status = HASH_ENGINE_UPDATE_FAILED;
			}
			break;
#endif

		case HASH_ACTIVE_SHA256:
			if (SHA256_Update (&openssl->sha256, data, length) == 1) {
				status = 0;
			}
			else {
				status = HASH_ENGINE_UPDATE_FAILED;
			}
			break;

		default:
			status = HASH_ENGINE_NO_ACTIVE_HASH;
			break;
	}

	return status;
}

static int hash_openssl_finish (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;
	int status;

	if ((openssl == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	switch (openssl->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			if (hash_length >= SHA1_HASH_LENGTH) {
				if (SHA1_Final (hash, &openssl->sha1) == 1) {
					status = 0;
				}
				else {
					status = HASH_ENGINE_FINISH_FAILED;
				}
			}
			else {
				status = HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}
			break;
#endif

		case HASH_ACTIVE_SHA256:
			if (hash_length >= SHA256_HASH_LENGTH) {
				if (SHA256_Final (hash, &openssl->sha256) == 1) {
					status = 0;
				}
				else {
					status = HASH_ENGINE_FINISH_FAILED;
				}
			}
			else {
				status = HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}
			break;

		default:
			status = HASH_ENGINE_NO_ACTIVE_HASH;
	}

	if (status == 0) {
		openssl->active = HASH_ACTIVE_NONE;
	}
	return status;
}

static void hash_openssl_cancel (struct hash_engine *engine)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if (openssl) {
		openssl->active = HASH_ACTIVE_NONE;
	}
}

/**
 * Initialize an OpenSSL engine for calculating hashes.
 *
 * @param engine The hash engine to initialize.
 *
 * @return 0 if the hash engine was initialize successfully or an error code.
 */
int hash_openssl_init (struct hash_engine_openssl *engine)
{
	if (engine == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	memset (engine, 0, sizeof (struct hash_engine_openssl));

#ifdef HASH_ENABLE_SHA1
	engine->base.calculate_sha1 = hash_openssl_calculate_sha1;
	engine->base.start_sha1 = hash_openssl_start_sha1;
#endif
	engine->base.calculate_sha256 = hash_openssl_calculate_sha256;
	engine->base.start_sha256 = hash_openssl_start_sha256;
	engine->base.update = hash_openssl_update;
	engine->base.finish = hash_openssl_finish;
	engine->base.cancel = hash_openssl_cancel;

	return 0;
}

/**
 * Release the resources used by an OpenSSL hash engine.
 *
 * @param engine The hash engine to release.
 */
void hash_openssl_release (struct hash_engine_openssl *engine)
{

}
