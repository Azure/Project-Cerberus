// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "aes_key_wrap_mock.h"


static int aes_key_wrap_mock_set_kek (const struct aes_key_wrap_interface *aes_kw,
	const uint8_t *kek, size_t length)
{
	struct aes_key_wrap_mock *mock = (struct aes_key_wrap_mock*) aes_kw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_key_wrap_mock_set_kek, aes_kw, MOCK_ARG_PTR_CALL (kek),
		MOCK_ARG_PTR_CALL (length));
}

static int aes_key_wrap_mock_clear_kek (const struct aes_key_wrap_interface *aes_kw)
{
	struct aes_key_wrap_mock *mock = (struct aes_key_wrap_mock*) aes_kw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, aes_key_wrap_mock_clear_kek, aes_kw);
}

static int aes_key_wrap_mock_wrap (const struct aes_key_wrap_interface *aes_kw, const uint8_t *data,
	size_t length, uint8_t *wrapped, size_t out_length)
{
	struct aes_key_wrap_mock *mock = (struct aes_key_wrap_mock*) aes_kw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_key_wrap_mock_wrap, aes_kw, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (wrapped), MOCK_ARG_CALL (out_length));
}

static int aes_key_wrap_mock_unwrap (const struct aes_key_wrap_interface *aes_kw,
	const uint8_t *wrapped, size_t length, uint8_t *data, size_t *out_length)
{
	struct aes_key_wrap_mock *mock = (struct aes_key_wrap_mock*) aes_kw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, aes_key_wrap_mock_unwrap, aes_kw, MOCK_ARG_PTR_CALL (wrapped),
		MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (data), MOCK_ARG_PTR_CALL (out_length));
}

static int aes_key_wrap_mock_func_arg_count (void *func)
{
	if ((func == aes_key_wrap_mock_wrap) || (func == aes_key_wrap_mock_unwrap)) {
		return 4;
	}
	else if (func == aes_key_wrap_mock_set_kek) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* aes_key_wrap_mock_func_name_map (void *func)
{
	if (func == aes_key_wrap_mock_set_kek) {
		return "set_kek";
	}
	else if (func == aes_key_wrap_mock_clear_kek) {
		return "clear_kek";
	}
	else if (func == aes_key_wrap_mock_wrap) {
		return "wrap";
	}
	else if (func == aes_key_wrap_mock_unwrap) {
		return "unwrap";
	}
	else {
		return "unknown";
	}
}

static const char* aes_key_wrap_mock_arg_name_map (void *func, int arg)
{
	if (func == aes_key_wrap_mock_set_kek) {
		switch (arg) {
			case 0:
				return "kek";

			case 1:
				return "length";
		}
	}
	else if (func == aes_key_wrap_mock_wrap) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";

			case 2:
				return "wrapped";

			case 3:
				return "out_length";
		}
	}
	else if (func == aes_key_wrap_mock_unwrap) {
		switch (arg) {
			case 0:
				return "wrapped";

			case 1:
				return "length";

			case 2:
				return "data";

			case 3:
				return "out_length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the AES key wrap API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int aes_key_wrap_mock_init (struct aes_key_wrap_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct aes_key_wrap_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "aes_key_wrap");

	mock->base.set_kek = aes_key_wrap_mock_set_kek;
	mock->base.clear_kek = aes_key_wrap_mock_clear_kek;
	mock->base.wrap = aes_key_wrap_mock_wrap;
	mock->base.unwrap = aes_key_wrap_mock_unwrap;

	mock->mock.func_arg_count = aes_key_wrap_mock_func_arg_count;
	mock->mock.func_name_map = aes_key_wrap_mock_func_name_map;
	mock->mock.arg_name_map = aes_key_wrap_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock AES key wrap API instance.
 *
 * @param mock The mock to release.
 */
void aes_key_wrap_mock_release (struct aes_key_wrap_mock *mock)
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
int aes_key_wrap_mock_validate_and_release (struct aes_key_wrap_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		aes_key_wrap_mock_release (mock);
	}

	return status;
}
