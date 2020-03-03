// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "aes_mock.h"


static int aes_mock_set_key (struct aes_engine *engine, const uint8_t *key, size_t length)
{
	struct aes_engine_mock *mock = (struct aes_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_mock_set_key, engine, MOCK_ARG_CALL (key),
		MOCK_ARG_CALL (length));
}

static int aes_mock_encrypt_data (struct aes_engine *engine, const uint8_t *plaintext,
	size_t length, const uint8_t *iv, size_t iv_length, uint8_t *ciphertext, size_t out_length,
	uint8_t *tag, size_t tag_length)
{
	struct aes_engine_mock *mock = (struct aes_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_mock_encrypt_data, engine, MOCK_ARG_CALL (plaintext),
		MOCK_ARG_CALL (length), MOCK_ARG_CALL (iv), MOCK_ARG_CALL (iv_length),
		MOCK_ARG_CALL (ciphertext), MOCK_ARG_CALL (out_length), MOCK_ARG_CALL (tag),
		MOCK_ARG_CALL (tag_length));
}

static int aes_mock_decrypt_data (struct aes_engine *engine, const uint8_t *ciphertext,
	size_t length, const uint8_t *tag, const uint8_t *iv, size_t iv_length, uint8_t *plaintext,
	size_t out_length)
{
	struct aes_engine_mock *mock = (struct aes_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_mock_decrypt_data, engine, MOCK_ARG_CALL (ciphertext),
		MOCK_ARG_CALL (length), MOCK_ARG_CALL (tag), MOCK_ARG_CALL (iv), MOCK_ARG_CALL (iv_length),
		MOCK_ARG_CALL (plaintext), MOCK_ARG_CALL (out_length));
}

static int aes_mock_func_arg_count (void *func)
{
	if (func == aes_mock_encrypt_data) {
		return 8;
	}
	else if (func == aes_mock_decrypt_data) {
		return 7;
	}
	else if (func == aes_mock_set_key) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* aes_mock_func_name_map (void *func)
{
	if (func == aes_mock_set_key) {
		return "set_key";
	}
	else if (func == aes_mock_encrypt_data) {
		return "encrypt_data";
	}
	else if (func == aes_mock_decrypt_data) {
		return "decrypt_data";
	}
	else {
		return "unknown";
	}
}

static const char* aes_mock_arg_name_map (void *func, int arg)
{
	if (func == aes_mock_set_key) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "length";

		}
	}
	else if (func == aes_mock_encrypt_data) {
		switch (arg) {
			case 0:
				return "plaintext";

			case 1:
				return "length";

			case 2:
				return "iv";

			case 3:
				return "iv_length";

			case 4:
				return "ciphertext";

			case 5:
				return "out_length";

			case 6:
				return "tag";

			case 7:
				return "tag_length";

		}
	}
	else if (func == aes_mock_decrypt_data) {
		switch (arg) {
			case 0:
				return "ciphertext";

			case 1:
				return "length";

			case 2:
				return "tag";

			case 3:
				return "iv";

			case 4:
				return "iv_length";

			case 5:
				return "plaintext";

			case 6:
				return "out_length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the AES API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int aes_mock_init (struct aes_engine_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct aes_engine_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "aes");

	mock->base.set_key = aes_mock_set_key;
	mock->base.encrypt_data = aes_mock_encrypt_data;
	mock->base.decrypt_data = aes_mock_decrypt_data;

	mock->mock.func_arg_count = aes_mock_func_arg_count;
	mock->mock.func_name_map = aes_mock_func_name_map;
	mock->mock.arg_name_map = aes_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock AES API instance.
 *
 * @param mock The mock to release.
 */
void aes_mock_release (struct aes_engine_mock *mock)
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
int aes_mock_validate_and_release (struct aes_engine_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		aes_mock_release (mock);
	}

	return status;
}
