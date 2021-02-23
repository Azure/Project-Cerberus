// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "authorization_mock.h"


static int authorization_mock_authorize (struct authorization *auth, uint8_t **token,
	size_t *length)
{
	struct authorization_mock *mock = (struct authorization_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, authorization_mock_authorize, auth, MOCK_ARG_CALL (token),
		MOCK_ARG_CALL (length));
}

static int authorization_mock_func_arg_count (void *func)
{
	if (func == authorization_mock_authorize) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* authorization_mock_func_name_map (void *func)
{
	if (func == authorization_mock_authorize) {
		return "authorize";
	}
	else {
		return "unknown";
	}
}

static const char* authorization_mock_arg_name_map (void *func, int arg)
{
	if (func == authorization_mock_authorize) {
		switch (arg) {
			case 0:
				return "token";

			case 1:
				return "length";

		}
	}

	return "unknown";
}

/**
 * Initialize a mock for clearing configuration files.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int authorization_mock_init (struct authorization_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct authorization_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "authorization");

	mock->base.authorize = authorization_mock_authorize;

	mock->mock.func_arg_count = authorization_mock_func_arg_count;
	mock->mock.func_name_map = authorization_mock_func_name_map;
	mock->mock.arg_name_map = authorization_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock configuration reset instance.
 *
 * @param mock The mock to release.
 */
void authorization_mock_release (struct authorization_mock *mock)
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
int authorization_mock_validate_and_release (struct authorization_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		authorization_mock_release (mock);
	}

	return status;
}
