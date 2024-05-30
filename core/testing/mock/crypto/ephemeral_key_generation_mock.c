// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "ephemeral_key_generation_mock.h"


static int ephemeral_key_generation_mock_generate_key (
	const struct ephemeral_key_generation *key_gen,	int bits, uint8_t **key, size_t *key_length)
{
	struct ephemeral_key_generation_mock *mock = (struct ephemeral_key_generation_mock*) key_gen;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ephemeral_key_generation_mock_generate_key, key_gen,
		MOCK_ARG_CALL (bits), MOCK_ARG_PTR_CALL (key), MOCK_ARG_PTR_CALL (key_length));
}



static int ephemeral_key_generation_mock_func_arg_count (void *func)
{
	if (func == ephemeral_key_generation_mock_generate_key) {
		return 3;
	}
	else {
		return 0;
	}
}

static const char* ephemeral_key_generation_mock_func_name_map (void *func)
{
	if (func == ephemeral_key_generation_mock_generate_key) {
		return "generate_key";
	}
	else {
		return "unknown";
	}
}

static const char* ephemeral_key_generation_mock_arg_name_map (void *func, int arg)
{
	if (func == ephemeral_key_generation_mock_generate_key) {
		switch (arg) {
			case 0:
				return "bits";

			case 1:
				return "key";

			case 2:
				return "key_length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the RSA API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int ephemeral_key_generation_mock_init (struct ephemeral_key_generation_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct ephemeral_key_generation_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "ephemeral_key_generation");

	mock->base.generate_key = ephemeral_key_generation_mock_generate_key;

	mock->mock.func_arg_count = ephemeral_key_generation_mock_func_arg_count;
	mock->mock.func_name_map = ephemeral_key_generation_mock_func_name_map;
	mock->mock.arg_name_map = ephemeral_key_generation_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock RSA API instance.
 *
 * @param mock The mock to release.
 */
void ephemeral_key_generation_mock_release (struct ephemeral_key_generation_mock *mock)
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
int ephemeral_key_generation_mock_validate_and_release (struct ephemeral_key_generation_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		ephemeral_key_generation_mock_release (mock);
	}

	return status;
}
