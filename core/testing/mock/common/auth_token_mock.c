// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "auth_token_mock.h"


static int auth_token_mock_new_token (const struct auth_token *auth, const uint8_t *data,
	size_t data_length, const uint8_t **token, size_t *length)
{
	struct auth_token_mock *mock = (struct auth_token_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, auth_token_mock_new_token, auth, MOCK_ARG_PTR_CALL (data),
		MOCK_ARG_CALL (data_length), MOCK_ARG_PTR_CALL (token), MOCK_ARG_PTR_CALL (length));
}

static int auth_token_mock_verify_data (const struct auth_token *auth, const uint8_t *authorized,
	size_t length, size_t token_offset, size_t aad_length, enum hash_type sig_hash)
{
	struct auth_token_mock *mock = (struct auth_token_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, auth_token_mock_verify_data, auth, MOCK_ARG_PTR_CALL (authorized),
		MOCK_ARG_CALL (length), MOCK_ARG_CALL (token_offset), MOCK_ARG_CALL (aad_length),
		MOCK_ARG_CALL (sig_hash));
}

static int auth_token_mock_invalidate (const struct auth_token *auth)
{
	struct auth_token_mock *mock = (struct auth_token_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, auth_token_mock_invalidate, auth);
}

static int auth_token_mock_func_arg_count (void *func)
{
	if (func == auth_token_mock_verify_data) {
		return 5;
	}
	else if (func == auth_token_mock_new_token) {
		return 4;
	}
	else {
		return 0;
	}
}

static const char* auth_token_mock_func_name_map (void *func)
{
	if (func == auth_token_mock_new_token) {
		return "new_token";
	}
	else if (func == auth_token_mock_verify_data) {
		return "verify_data";
	}
	else if (func == auth_token_mock_invalidate) {
		return "invalidate";
	}
	else {
		return "unknown";
	}
}

static const char* auth_token_mock_arg_name_map (void *func, int arg)
{
	if (func == auth_token_mock_new_token) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "data_length";

			case 2:
				return "token";

			case 3:
				return "length";
		}
	}
	else if (func == auth_token_mock_verify_data) {
		switch (arg) {
			case 0:
				return "authorized";

			case 1:
				return "length";

			case 2:
				return "token_offset";

			case 3:
				return "aad_length";

			case 4:
				return "sig_hash";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for handling authorization tokens.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int auth_token_mock_init (struct auth_token_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct auth_token_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "auth_token");

	mock->base.new_token = auth_token_mock_new_token;
	mock->base.verify_data = auth_token_mock_verify_data;
	mock->base.invalidate = auth_token_mock_invalidate;

	mock->mock.func_arg_count = auth_token_mock_func_arg_count;
	mock->mock.func_name_map = auth_token_mock_func_name_map;
	mock->mock.arg_name_map = auth_token_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock authorization token handler.
 *
 * @param mock The mock to release.
 */
void auth_token_mock_release (struct auth_token_mock *mock)
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
int auth_token_mock_validate_and_release (struct auth_token_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		auth_token_mock_release (mock);
	}

	return status;
}
