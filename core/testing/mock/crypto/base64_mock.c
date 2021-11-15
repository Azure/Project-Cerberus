// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "base64_mock.h"


static int base64_mock_encode (struct base64_engine *engine, const uint8_t *data, size_t length,
	uint8_t *encoded, size_t enc_length)
{
	struct base64_engine_mock *mock = (struct base64_engine_mock*) engine;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, base64_mock_encode, engine, MOCK_ARG_CALL (data),
		MOCK_ARG_CALL (length), MOCK_ARG_CALL (encoded), MOCK_ARG_CALL (enc_length));
}

static int base64_mock_func_arg_count (void *func)
{
	if (func == base64_mock_encode) {
		return 4;
	}
	else {
		return 0;
	}
}

static const char* base64_mock_func_name_map (void *func)
{
	if (func == base64_mock_encode) {
		return "encode";
	}
	else {
		return "unknown";
	}
}

static const char* base64_mock_arg_name_map (void *func, int arg)
{
	if (func == base64_mock_encode) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";

			case 2:
				return "encoded";

			case 3:
				return "enc_length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the base64 API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int base64_mock_init (struct base64_engine_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct base64_engine_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "base64");

	mock->base.encode = base64_mock_encode;

	mock->mock.func_arg_count = base64_mock_func_arg_count;
	mock->mock.func_name_map = base64_mock_func_name_map;
	mock->mock.arg_name_map = base64_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock base64 API instance.
 *
 * @param mock The mock to release.
 */
void base64_mock_release (struct base64_engine_mock *mock)
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
int base64_mock_validate_and_release (struct base64_engine_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		base64_mock_release (mock);
	}

	return status;
}
