// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "authorized_execution_mock.h"


static int authorized_execution_mock_execute (const struct authorized_execution *execution)
{
	struct authorized_execution_mock *mock = (struct authorized_execution_mock*) execution;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, authorized_execution_mock_execute, execution);
}

static void authorized_execution_mock_get_status_identifiers (
	const struct authorized_execution *execution, uint8_t *start, uint8_t *error)
{
	struct authorized_execution_mock *mock = (struct authorized_execution_mock*) execution;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, authorized_execution_mock_get_status_identifiers, execution,
		MOCK_ARG_PTR_CALL (start), MOCK_ARG_PTR_CALL (error));
}

static int authorized_execution_mock_func_arg_count (void *func)
{
	if (func == authorized_execution_mock_get_status_identifiers) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* authorized_execution_mock_func_name_map (void *func)
{
	if (func == authorized_execution_mock_execute) {
		return "execute";
	}
	else if (func == authorized_execution_mock_get_status_identifiers) {
		return "get_status_identifiers";
	}
	else {
		return "unknown";
	}
}

static const char* authorized_execution_mock_arg_name_map (void *func, int arg)
{
	if (func == authorized_execution_mock_get_status_identifiers) {
		switch (arg) {
			case 0:
				return "start";

			case 1:
				return "error";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for executing authorized executions.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int authorized_execution_mock_init (struct authorized_execution_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct authorized_execution_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "authorized_execution");

	mock->base.execute = authorized_execution_mock_execute;
	mock->base.get_status_identifiers = authorized_execution_mock_get_status_identifiers;

	mock->mock.func_arg_count = authorized_execution_mock_func_arg_count;
	mock->mock.func_name_map = authorized_execution_mock_func_name_map;
	mock->mock.arg_name_map = authorized_execution_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock authorized execution instance.
 *
 * @param mock The mock to release.
 */
void authorized_execution_mock_release (struct authorized_execution_mock *mock)
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
int authorized_execution_mock_validate_and_release (struct authorized_execution_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		authorized_execution_mock_release (mock);
	}

	return status;
}
