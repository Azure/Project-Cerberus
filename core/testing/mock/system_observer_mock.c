// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "system_observer_mock.h"


static void system_observer_mock_on_shutdown (struct system_observer *observer)
{
	struct system_observer_mock *mock = (struct system_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, system_observer_mock_on_shutdown, observer);
}

static int system_observer_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* system_observer_mock_func_name_map (void *func)
{
	if (func == system_observer_mock_on_shutdown) {
		return "on_shutdown";
	}
	else {
		return "unknown";
	}
}

static const char* system_observer_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize a mock for receiving system notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int system_observer_mock_init (struct system_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct system_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "system_observer");

	mock->base.on_shutdown = system_observer_mock_on_shutdown;

	mock->mock.func_arg_count = system_observer_mock_func_arg_count;
	mock->mock.func_name_map = system_observer_mock_func_name_map;
	mock->mock.arg_name_map = system_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a system observer mock.
 *
 * @param mock The mock to release.
 */
void system_observer_mock_release (struct system_observer_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate the expectations on the mock and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int system_observer_mock_validate_and_release (struct system_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		system_observer_mock_release (mock);
	}

	return status;
}
