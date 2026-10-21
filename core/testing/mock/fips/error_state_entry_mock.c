// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "error_state_entry_mock.h"


static void error_state_entry_mock_enter_error_state (
	const struct error_state_entry_interface *entry, const struct debug_log_entry_info *error_log)
{
	struct error_state_entry_mock *mock = (struct error_state_entry_mock*) entry;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, error_state_entry_mock_enter_error_state, entry,
		MOCK_ARG_PTR_CALL (error_log));
}

static int error_state_entry_mock_func_arg_count (void *func)
{
	if (func == error_state_entry_mock_enter_error_state) {
		return 1;
	}

	return 0;
}

static const char* error_state_entry_mock_func_name_map (void *func)
{
	if (func == error_state_entry_mock_enter_error_state) {
		return "enter_error_state";
	}
	else {
		return "unknown";
	}
}

static const char* error_state_entry_mock_arg_name_map (void *func, int arg)
{
	if (func == error_state_entry_mock_enter_error_state) {
		switch (arg) {
			case 0:
				return "error_log";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the FIPS error state entry API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int error_state_entry_mock_init (struct error_state_entry_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct error_state_entry_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "error_state_entry");

	mock->base.enter_error_state = error_state_entry_mock_enter_error_state;

	mock->mock.func_arg_count = error_state_entry_mock_func_arg_count;
	mock->mock.func_name_map = error_state_entry_mock_func_name_map;
	mock->mock.arg_name_map = error_state_entry_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock FIPS error state entry API instance.
 *
 * @param mock The mock to release.
 */
void error_state_entry_mock_release (struct error_state_entry_mock *mock)
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
int error_state_entry_mock_validate_and_release (struct error_state_entry_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		error_state_entry_mock_release (mock);
	}

	return status;
}
