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
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if ((openssl == NULL) || ((data == NULL) && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (openssl->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
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

	if (openssl->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (EVP_DigestInit (openssl->sha, EVP_sha1 ()) == 1) {
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
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if ((openssl == NULL) || ((data == NULL)  && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (openssl->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
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

	if (openssl->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (EVP_DigestInit (openssl->sha, EVP_sha256 ()) == 1) {
		openssl->active = HASH_ACTIVE_SHA256;
		return 0;
	}
	else {
		return HASH_ENGINE_START_SHA256_FAILED;
	}
}

#ifdef HASH_ENABLE_SHA384
static int hash_openssl_calculate_sha384 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if ((openssl == NULL) || ((data == NULL)  && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (openssl->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA384_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	SHA384 (data, length, hash);

	return 0;
}

static int hash_openssl_start_sha384 (struct hash_engine *engine)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if (openssl == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (openssl->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (EVP_DigestInit (openssl->sha, EVP_sha384 ()) == 1) {
		openssl->active = HASH_ACTIVE_SHA384;
		return 0;
	}
	else {
		return HASH_ENGINE_START_SHA384_FAILED;
	}
}
#endif

#ifdef HASH_ENABLE_SHA512
static int hash_openssl_calculate_sha512 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if ((openssl == NULL) || ((data == NULL)  && (length != 0)) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (openssl->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (hash_length < SHA512_HASH_LENGTH) {
		return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
	}

	SHA512 (data, length, hash);

	return 0;
}

static int hash_openssl_start_sha512 (struct hash_engine *engine)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;

	if (openssl == NULL) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (openssl->active != HASH_ACTIVE_NONE) {
		return HASH_ENGINE_HASH_IN_PROGRESS;
	}

	if (EVP_DigestInit (openssl->sha, EVP_sha512 ()) == 1) {
		openssl->active = HASH_ACTIVE_SHA512;
		return 0;
	}
	else {
		return HASH_ENGINE_START_SHA512_FAILED;
	}
}
#endif

static int hash_openssl_update (struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;
	int status;

	if ((openssl == NULL) || ((data == NULL) && (length != 0))) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (openssl->active == HASH_ACTIVE_NONE) {
		return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	status = EVP_DigestUpdate (openssl->sha, data, length);
	if (status == 1) {
		return 0;
	}
	else {
		return HASH_ENGINE_UPDATE_FAILED;
	}
}

/**
 * Check the length of an output buffer to ensure it is large enough for the generated hash.
 *
 * @param openssl The hash instance that will be generating the output hash.
 * @param hash_length Length of the output buffer to check.
 *
 * @return 0 if the buffer is large enough for the hash or an error code.
 */
static int hash_openssl_check_output_buffer_length (const struct hash_engine_openssl *openssl,
	size_t hash_length)
{
	switch (openssl->active) {
#ifdef HASH_ENABLE_SHA1
		case HASH_ACTIVE_SHA1:
			if (hash_length < SHA1_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}
			break;
#endif

		case HASH_ACTIVE_SHA256:
			if (hash_length < SHA256_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_ACTIVE_SHA384:
			if (hash_length < SHA384_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_ACTIVE_SHA512:
			if (hash_length < SHA512_HASH_LENGTH) {
				return HASH_ENGINE_HASH_BUFFER_TOO_SMALL;
			}
			break;
#endif

		default:
			return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	return 0;
}

static int hash_openssl_get_hash (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;
	EVP_MD_CTX *clone;
	int status;

	if ((openssl == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	if (openssl->active == HASH_ACTIVE_NONE) {
		return HASH_ENGINE_NO_ACTIVE_HASH;
	}

	status = hash_openssl_check_output_buffer_length (openssl, hash_length);
	if (status != 0) {
		return status;
	}

	clone = EVP_MD_CTX_new ();
	if (clone == NULL) {
		return HASH_ENGINE_NO_MEMORY;
	}

	status = EVP_MD_CTX_copy (clone, openssl->sha);
	if (status == 0) {
		status = HASH_ENGINE_GET_HASH_FAILED;
		goto exit;
	}

	status = EVP_DigestFinal (clone, hash, NULL);
	if (status == 1) {
		status = 0;
	}
	else {
		status = HASH_ENGINE_GET_HASH_FAILED;
	}

exit:
	EVP_MD_CTX_free (clone);
	return status;
}

static int hash_openssl_finish (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_openssl *openssl = (struct hash_engine_openssl*) engine;
	int status = 0;

	if ((openssl == NULL) || (hash == NULL)) {
		return HASH_ENGINE_INVALID_ARGUMENT;
	}

	status = hash_openssl_check_output_buffer_length (openssl, hash_length);
	if (status != 0) {
		return status;
	}

	status = EVP_DigestFinal (openssl->sha, hash, NULL);
	if (status == 1) {
		openssl->active = HASH_ACTIVE_NONE;
		status = 0;
	}
	else if (status == 0) {
		status = HASH_ENGINE_FINISH_FAILED;
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

	engine->sha = EVP_MD_CTX_new ();
	if (engine->sha == NULL) {
		return HASH_ENGINE_NO_MEMORY;
	}

#ifdef HASH_ENABLE_SHA1
	engine->base.calculate_sha1 = hash_openssl_calculate_sha1;
	engine->base.start_sha1 = hash_openssl_start_sha1;
#endif
	engine->base.calculate_sha256 = hash_openssl_calculate_sha256;
	engine->base.start_sha256 = hash_openssl_start_sha256;
#ifdef HASH_ENABLE_SHA384
	engine->base.calculate_sha384 = hash_openssl_calculate_sha384;
	engine->base.start_sha384 = hash_openssl_start_sha384;
#endif
#ifdef HASH_ENABLE_SHA512
	engine->base.calculate_sha512 = hash_openssl_calculate_sha512;
	engine->base.start_sha512 = hash_openssl_start_sha512;
#endif
	engine->base.update = hash_openssl_update;
	engine->base.get_hash = hash_openssl_get_hash;
	engine->base.finish = hash_openssl_finish;
	engine->base.cancel = hash_openssl_cancel;

	engine->active = HASH_ACTIVE_NONE;

	return 0;
}

/**
 * Release the resources used by an OpenSSL hash engine.
 *
 * @param engine The hash engine to release.
 */
void hash_openssl_release (struct hash_engine_openssl *engine)
{
	if (engine != NULL) {
		EVP_MD_CTX_free (engine->sha);
	}
}
