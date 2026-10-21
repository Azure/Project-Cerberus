// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "error_state_exit_mock.h"


static int error_state_exit_mock_exit_error_state (const struct error_state_exit_interface *exit)
{
	struct error_state_exit_mock *mock = (struct error_state_exit_mock*) exit;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, error_state_exit_mock_exit_error_state, exit);
}

static int error_state_exit_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* error_state_exit_mock_func_name_map (void *func)
{
	if (func == error_state_exit_mock_exit_error_state) {
		return "exit_error_state";
	}
	else {
		return "unknown";
	}
}

static const char* error_state_exit_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize a mock for the FIPS error state exit API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int error_state_exit_mock_init (struct error_state_exit_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct error_state_exit_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "error_state_exit");

	mock->base.exit_error_state = error_state_exit_mock_exit_error_state;

	mock->mock.func_arg_count = error_state_exit_mock_func_arg_count;
	mock->mock.func_name_map = error_state_exit_mock_func_name_map;
	mock->mock.arg_name_map = error_state_exit_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock FIPS error state exit API instance.
 *
 * @param mock The mock to release.
 */
void error_state_exit_mock_release (struct error_state_exit_mock *mock)
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
int error_state_exit_mock_validate_and_release (struct error_state_exit_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		error_state_exit_mock_release (mock);
	}

	return status;
}
