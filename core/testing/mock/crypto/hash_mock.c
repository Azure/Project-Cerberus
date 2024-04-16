// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "hash_mock.h"


static int hash_mock_calculate_sha1 (struct hash_engine *engine, const uint8_t *data, size_t length,
	uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hash_mock_calculate_sha1, engine, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_length));
}

static int hash_mock_start_sha1 (struct hash_engine *engine)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, hash_mock_start_sha1, engine);
}

static int hash_mock_calculate_sha256 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hash_mock_calculate_sha256, engine, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_length));
}

static int hash_mock_start_sha256 (struct hash_engine *engine)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, hash_mock_start_sha256, engine);
}

static int hash_mock_calculate_sha384 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hash_mock_calculate_sha384, engine, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_length));
}

static int hash_mock_start_sha384 (struct hash_engine *engine)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, hash_mock_start_sha384, engine);
}

static int hash_mock_calculate_sha512 (struct hash_engine *engine, const uint8_t *data,
	size_t length, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hash_mock_calculate_sha512, engine, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (hash), MOCK_ARG_CALL (hash_length));
}

static int hash_mock_start_sha512 (struct hash_engine *engine)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, hash_mock_start_sha512, engine);
}

static int hash_mock_update (struct hash_engine *engine, const uint8_t *data, size_t length)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hash_mock_update, engine, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (length));
}

static int hash_mock_finish (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hash_mock_finish, engine, MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_CALL (hash_length));
}

static void hash_mock_cancel (struct hash_engine *engine)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, hash_mock_cancel, engine);
}

static int hash_mock_get_hash (struct hash_engine *engine, uint8_t *hash, size_t hash_length)
{
	struct hash_engine_mock *mock = (struct hash_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hash_mock_get_hash, engine, MOCK_ARG_PTR_CALL (hash),
		MOCK_ARG_CALL (hash_length));
}

static int hash_mock_func_arg_count (void *func)
{
	if ((func == hash_mock_calculate_sha1) || (func == hash_mock_calculate_sha256) ||
		(func == hash_mock_calculate_sha384) || (func == hash_mock_calculate_sha512)) {
		return 4;
	}
	else if ((func == hash_mock_update) || (func == hash_mock_finish) ||
		(func == hash_mock_get_hash)) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* hash_mock_func_name_map (void *func)
{
	if (func == hash_mock_calculate_sha1) {
		return "calculate_sha1";
	}
	else if (func == hash_mock_start_sha1) {
		return "start_sha1";
	}
	else if (func == hash_mock_calculate_sha256) {
		return "calculate_sha256";
	}
	else if (func == hash_mock_start_sha256) {
		return "start_sha256";
	}
	else if (func == hash_mock_calculate_sha384) {
		return "calculate_sha384";
	}
	else if (func == hash_mock_start_sha384) {
		return "start_sha384";
	}
	else if (func == hash_mock_calculate_sha512) {
		return "calculate_sha512";
	}
	else if (func == hash_mock_start_sha512) {
		return "start_sha512";
	}
	else if (func == hash_mock_update) {
		return "update";
	}
	else if (func == hash_mock_finish) {
		return "finish";
	}
	else if (func == hash_mock_cancel) {
		return "cancel";
	}
	else if (func == hash_mock_get_hash) {
		return "get_hash";
	}
	else {
		return "unknown";
	}
}

static const char* hash_mock_arg_name_map (void *func, int arg)
{
	if (func == hash_mock_calculate_sha1) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";

			case 2:
				return "hash";

			case 3:
				return "hash_length";
		}
	}
	else if (func == hash_mock_calculate_sha256) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";

			case 2:
				return "hash";

			case 3:
				return "hash_length";
		}
	}
	else if (func == hash_mock_calculate_sha384) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";

			case 2:
				return "hash";

			case 3:
				return "hash_length";
		}
	}
	else if (func == hash_mock_calculate_sha512) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";

			case 2:
				return "hash";

			case 3:
				return "hash_length";
		}
	}
	else if (func == hash_mock_update) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";
		}
	}
	else if ((func == hash_mock_finish) || (func == hash_mock_get_hash)) {
		switch (arg) {
			case 0:
				return "hash";

			case 1:
				return "hash_length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the hash API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int hash_mock_init (struct hash_engine_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct hash_engine_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "hash");

#ifdef HASH_ENABLE_SHA1
	mock->base.calculate_sha1 = hash_mock_calculate_sha1;
	mock->base.start_sha1 = hash_mock_start_sha1;
#endif
	mock->base.calculate_sha256 = hash_mock_calculate_sha256;
	mock->base.start_sha256 = hash_mock_start_sha256;
#ifdef HASH_ENABLE_SHA384
	mock->base.calculate_sha384 = hash_mock_calculate_sha384;
	mock->base.start_sha384 = hash_mock_start_sha384;
#endif
#ifdef HASH_ENABLE_SHA512
	mock->base.calculate_sha512 = hash_mock_calculate_sha512;
	mock->base.start_sha512 = hash_mock_start_sha512;
#endif
	mock->base.update = hash_mock_update;
	mock->base.finish = hash_mock_finish;
	mock->base.cancel = hash_mock_cancel;
	mock->base.get_hash = hash_mock_get_hash;

	mock->mock.func_arg_count = hash_mock_func_arg_count;
	mock->mock.func_name_map = hash_mock_func_name_map;
	mock->mock.arg_name_map = hash_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock hash API instance.
 *
 * @param mock The mock to release.
 */
void hash_mock_release (struct hash_engine_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int hash_mock_validate_and_release (struct hash_engine_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		hash_mock_release (mock);
	}

	return status;
}

/**
 * Add expectations to initialize an HMAC.
 *
 * @param mock The mock to use for the HMAC.
 * @param key The HMAC key.
 * @param key_length he length of the HMAC key.
 * @param hmac_algo The hash algorithm to use for the HMAC.
 *
 * @return 0 if the expectations were added successfully or an error code.
 */
int hash_mock_expect_hmac_init (struct hash_engine_mock *mock, const uint8_t *key,
	size_t key_length, enum hash_type hmac_algo)
{
	int status;
	uint8_t hmac_key[SHA512_BLOCK_SIZE];
	size_t hmac_key_length = sizeof (hmac_key);
	size_t i;

	switch (hmac_algo) {
#ifdef HASH_ENABLE_SHA1
		case HASH_TYPE_SHA1:
			status = mock_expect (&mock->mock, mock->base.start_sha1, mock, 0);
			hmac_key_length = SHA1_BLOCK_SIZE;
			break;
#endif

		case HASH_TYPE_SHA256:
			status = mock_expect (&mock->mock, mock->base.start_sha256, mock, 0);
			hmac_key_length = SHA256_BLOCK_SIZE;
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_TYPE_SHA384:
			status = mock_expect (&mock->mock, mock->base.start_sha384, mock, 0);
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_TYPE_SHA512:
			status = mock_expect (&mock->mock, mock->base.start_sha512, mock, 0);
			break;
#endif

		default:
			return HASH_ENGINE_UNKNOWN_HASH;
	}

	memset (hmac_key, 0x36, sizeof (hmac_key));
	for (i = 0; i < key_length; i++) {
		hmac_key[i] ^= key[i];
	}

	status |= mock_expect (&mock->mock, mock->base.update, mock, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (hmac_key, hmac_key_length), MOCK_ARG (hmac_key_length));

	return status;
}

/**
 * Add expectations to finish an HMAC.
 *
 * @param mock The mock to use for the HMAC.
 * @param key The HMAC key.
 * @param key_length The length of the HMAC key.
 * @param hmac The expected HMAC output buffer.  Set to null if the output buffer pointer is unknown.
 * @param hmac_length The expected length of the output buffer.
 * @param hmac_algo The hash algorithm to use for the HMAC.
 * @param expected The expected HMAC output to generate.
 * @param exp_length The length of the HMAC output.
 *
 * @return 0 if the expectations were added successfully or an error code.
 */
int hash_mock_expect_hmac_finish (struct hash_engine_mock *mock, const uint8_t *key,
	size_t key_length, uint8_t *hmac, size_t hmac_length, enum hash_type hmac_algo,
	const uint8_t *expected, size_t exp_length)
{
	int status;
	uint8_t hmac_key[SHA512_BLOCK_SIZE];
	size_t hmac_key_length = sizeof (hmac_key);
	size_t i;
	int inner = mock_expect_next_save_id (&mock->mock);
	int inner_length = hash_get_hash_length (hmac_algo);

	status = mock_expect (&mock->mock, mock->base.finish, mock, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (inner_length));
	status |= mock_expect_save_arg (&mock->mock, 0, inner);

	switch (hmac_algo) {
#ifdef HASH_ENABLE_SHA1
		case HASH_TYPE_SHA1:
			status |= mock_expect (&mock->mock, mock->base.start_sha1, mock, 0);
			hmac_key_length = SHA256_BLOCK_SIZE;
			break;
#endif

		case HASH_TYPE_SHA256:
			status |= mock_expect (&mock->mock, mock->base.start_sha256, mock, 0);
			hmac_key_length = SHA256_BLOCK_SIZE;
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_TYPE_SHA384:
			status |= mock_expect (&mock->mock, mock->base.start_sha384, mock, 0);
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_TYPE_SHA512:
			status |= mock_expect (&mock->mock, mock->base.start_sha512, mock, 0);
			break;
#endif

		default:
			return HASH_ENGINE_UNKNOWN_HASH;
	}

	memset (hmac_key, 0x5c, sizeof (hmac_key));
	for (i = 0; i < key_length; i++) {
		hmac_key[i] ^= key[i];
	}
	status |= mock_expect (&mock->mock, mock->base.update, mock, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (hmac_key, hmac_key_length), MOCK_ARG (hmac_key_length));

	status |= mock_expect (&mock->mock, mock->base.update, mock, 0, MOCK_ARG_SAVED_ARG (inner),
		MOCK_ARG (inner_length));

	if (hmac != NULL) {
		status |= mock_expect (&mock->mock, mock->base.finish, mock, 0, MOCK_ARG_PTR (hmac),
			MOCK_ARG (hmac_length));
	}
	else {
		status |= mock_expect (&mock->mock, mock->base.finish, mock, 0, MOCK_ARG_NOT_NULL,
			MOCK_ARG_AT_LEAST (hmac_length));
	}
	status |= mock_expect_output (&mock->mock, 0, expected, exp_length, 1);

	return status;
}

/**
 * Add expectations to run an HMAC with the mock hash engine.
 *
 * @param mock The mock to use for the HMAC.
 * @param key The HMAC key.
 * @param key_length The length of the HMAC key.
 * @param data The data for the HMAC.
 * @param length The length of the data.
 * @param hmac The expected HMAC output buffer.  Set to null if the output buffer pointer is unknown.
 * @param hmac_length The expected length of the output buffer.
 * @param hmac_algo The hash algorithm to use for the HMAC.
 * @param expected The expected HMAC output to generate.
 * @param exp_length The length of the HMAC output.
 *
 * @return 0 if the expectations were added successfully or an error code.
 */
int hash_mock_expect_hmac (struct hash_engine_mock *mock, const uint8_t *key, size_t key_length,
	const uint8_t *data, size_t length, uint8_t *hmac, size_t hmac_length, enum hash_type hmac_algo,
	const uint8_t *expected, size_t exp_length)
{
	int status;

	status = hash_mock_expect_hmac_init (mock, key, key_length, hmac_algo);

	status |= mock_expect (&mock->mock, mock->base.update, mock, 0,
		MOCK_ARG_PTR_CONTAINS (data, length), MOCK_ARG (length));

	status |= hash_mock_expect_hmac_finish (mock, key, key_length, hmac, hmac_length, hmac_algo,
		expected, exp_length);

	return status;
}

/**
 * Add expectations to run an HMAC with the mock hash engine when the input key is larger than the
 * the hash block size.
 *
 * @param mock The mock to use for the HMAC.
 * @param key The HMAC key.
 * @param key_length The length of the HMAC key.
 * @param key_digest The expected digest of the large HMAC key
 * @param data The data for the HMAC.
 * @param length The length of the data.
 * @param hmac The expected HMAC output buffer.  Set to null if the output buffer pointer is unknown.
 * @param hmac_length The expected length of the output buffer.
 * @param hmac_algo The hash algorithm to use for the HMAC.
 * @param expected The expected HMAC output to generate.
 * @param exp_length The length of the HMAC output.
 *
 * @return 0 if the expectations were added successfully or an error code.
 */
int hash_mock_expect_hmac_large_key (struct hash_engine_mock *mock, const uint8_t *key,
	size_t key_length, const uint8_t *key_digest, const uint8_t *data, size_t length, uint8_t *hmac,
	size_t hmac_length, enum hash_type hmac_algo, const uint8_t *expected, size_t exp_length)
{
	size_t digest_length;
	int status = 0;

	switch (hmac_algo) {
#ifdef HASH_ENABLE_SHA1
		case HASH_TYPE_SHA1:
			status = mock_expect (&mock->mock, mock->base.calculate_sha1, mock, 0,
				MOCK_ARG_PTR_CONTAINS (key, key_length), MOCK_ARG (key_length), MOCK_ARG_NOT_NULL,
				MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
			digest_length = SHA1_HASH_LENGTH;
			break;
#endif

		case HASH_TYPE_SHA256:
			status = mock_expect (&mock->mock, mock->base.calculate_sha256, mock, 0,
				MOCK_ARG_PTR_CONTAINS (key, key_length), MOCK_ARG (key_length), MOCK_ARG_NOT_NULL,
				MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
			digest_length = SHA256_HASH_LENGTH;
			break;

#ifdef HASH_ENABLE_SHA384
		case HASH_TYPE_SHA384:
			status = mock_expect (&mock->mock, mock->base.calculate_sha384, mock, 0,
				MOCK_ARG_PTR_CONTAINS (key, key_length), MOCK_ARG (key_length), MOCK_ARG_NOT_NULL,
				MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
			digest_length = SHA384_HASH_LENGTH;
			break;
#endif

#ifdef HASH_ENABLE_SHA512
		case HASH_TYPE_SHA512:
			status = mock_expect (&mock->mock, mock->base.calculate_sha512, mock, 0,
				MOCK_ARG_PTR_CONTAINS (key, key_length), MOCK_ARG (key_length), MOCK_ARG_NOT_NULL,
				MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
			digest_length = SHA512_HASH_LENGTH;
			break;
#endif

		default:
			return HASH_ENGINE_UNKNOWN_HASH;
	}

	status |= mock_expect_output (&mock->mock, 2, key_digest, digest_length, 3);

	status |= hash_mock_expect_hmac_init (mock, key_digest, digest_length, hmac_algo);

	status |= mock_expect (&mock->mock, mock->base.update, mock, 0,
		MOCK_ARG_PTR_CONTAINS (data, length), MOCK_ARG (length));

	status |= hash_mock_expect_hmac_finish (mock, key_digest, digest_length, hmac, hmac_length,
		hmac_algo, expected, exp_length);

	return status;
}
