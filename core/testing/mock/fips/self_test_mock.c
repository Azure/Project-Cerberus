// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "self_test_mock.h"


static int self_test_mock_run_self_test (const struct self_test_interface *self_test,
	struct debug_log_entry_info *error_info)
{
	struct self_test_mock *mock = (struct self_test_mock*) self_test;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, self_test_mock_run_self_test, self_test,
		MOCK_ARG_PTR_CALL (error_info));
}

static int self_test_mock_func_arg_count (void *func)
{
	if (func == self_test_mock_run_self_test) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* self_test_mock_func_name_map (void *func)
{
	if (func == self_test_mock_run_self_test) {
		return "run_self_test";
	}
	else {
		return "unknown";
	}
}

static const char* self_test_mock_arg_name_map (void *func, int arg)
{
	if (func == self_test_mock_run_self_test) {
		switch (arg) {
			case 0:
				return "error_info";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the self-test API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int self_test_mock_init (struct self_test_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct self_test_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "self_test");

	mock->base.run_self_test = self_test_mock_run_self_test;

	mock->mock.func_arg_count = self_test_mock_func_arg_count;
	mock->mock.func_name_map = self_test_mock_func_name_map;
	mock->mock.arg_name_map = self_test_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock self-test API instance.
 *
 * @param mock The mock to release.
 */
void self_test_mock_release (struct self_test_mock *mock)
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
int self_test_mock_validate_and_release (struct self_test_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		self_test_mock_release (mock);
	}

	return status;
}
