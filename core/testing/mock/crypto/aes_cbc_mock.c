// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes_cbc_mock.h"


static int aes_cbc_mock_set_key (const struct aes_cbc_engine *engine, const uint8_t *key,
	size_t length)
{
	struct aes_cbc_engine_mock *mock = (struct aes_cbc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_cbc_mock_set_key, engine, MOCK_ARG_PTR_CALL (key),
		MOCK_ARG_CALL (length));
}

static int aes_cbc_mock_encrypt_data (const struct aes_cbc_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t iv[AES_CBC_BLOCK_SIZE], uint8_t *ciphertext, size_t out_length,
	uint8_t out_iv[AES_CBC_BLOCK_SIZE])
{
	struct aes_cbc_engine_mock *mock = (struct aes_cbc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_cbc_mock_encrypt_data, engine, MOCK_ARG_PTR_CALL (plaintext),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (iv), MOCK_ARG_PTR_CALL (ciphertext),
		MOCK_ARG_CALL (out_length), MOCK_ARG_PTR_CALL (out_iv));
}

static int aes_cbc_mock_decrypt_data (const struct aes_cbc_engine *engine,
	const uint8_t *ciphertext, size_t length, const uint8_t iv[AES_CBC_BLOCK_SIZE],
	uint8_t *plaintext, size_t out_length, uint8_t out_iv[AES_CBC_BLOCK_SIZE])
{
	struct aes_cbc_engine_mock *mock = (struct aes_cbc_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_cbc_mock_decrypt_data, engine, MOCK_ARG_PTR_CALL (ciphertext),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (iv), MOCK_ARG_PTR_CALL (plaintext),
		MOCK_ARG_CALL (out_length), MOCK_ARG_PTR_CALL (out_iv));
}

static int aes_cbc_mock_func_arg_count (void *func)
{
	if ((func == aes_cbc_mock_encrypt_data) || (func == aes_cbc_mock_decrypt_data)) {
		return 6;
	}
	else if (func == aes_cbc_mock_set_key) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* aes_cbc_mock_func_name_map (void *func)
{
	if (func == aes_cbc_mock_set_key) {
		return "set_key";
	}
	else if (func == aes_cbc_mock_encrypt_data) {
		return "encrypt_data";
	}
	else if (func == aes_cbc_mock_decrypt_data) {
		return "decrypt_data";
	}
	else {
		return "unknown";
	}
}

static const char* aes_cbc_mock_arg_name_map (void *func, int arg)
{
	if (func == aes_cbc_mock_set_key) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "length";
		}
	}
	else if (func == aes_cbc_mock_encrypt_data) {
		switch (arg) {
			case 0:
				return "plaintext";

			case 1:
				return "length";

			case 2:
				return "iv";

			case 3:
				return "ciphertext";

			case 4:
				return "out_length";

			case 5:
				return "out_iv";
		}
	}
	else if (func == aes_cbc_mock_decrypt_data) {
		switch (arg) {
			case 0:
				return "ciphertext";

			case 1:
				return "length";

			case 2:
				return "iv";

			case 3:
				return "plaintext";

			case 4:
				return "out_length";

			case 5:
				return "out_iv";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the AES-CBC API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int aes_cbc_mock_init (struct aes_cbc_engine_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct aes_cbc_engine_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "aes_cbc");

	mock->base.set_key = aes_cbc_mock_set_key;
	mock->base.encrypt_data = aes_cbc_mock_encrypt_data;
	mock->base.decrypt_data = aes_cbc_mock_decrypt_data;

	mock->mock.func_arg_count = aes_cbc_mock_func_arg_count;
	mock->mock.func_name_map = aes_cbc_mock_func_name_map;
	mock->mock.arg_name_map = aes_cbc_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock AES-CBC API instance.
 *
 * @param mock The mock to release.
 */
void aes_cbc_mock_release (struct aes_cbc_engine_mock *mock)
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
int aes_cbc_mock_validate_and_release (struct aes_cbc_engine_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		aes_cbc_mock_release (mock);
	}

	return status;
}
