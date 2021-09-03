// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_processor_observer_mock.h"


static void host_processor_observer_mock_on_soft_reset (struct host_processor_observer *observer)
{
	struct host_processor_observer_mock *mock = (struct host_processor_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, host_processor_observer_mock_on_soft_reset, observer);
}

static void host_processor_observer_mock_on_bypass_mode (struct host_processor_observer *observer)
{
	struct host_processor_observer_mock *mock = (struct host_processor_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, host_processor_observer_mock_on_bypass_mode, observer);
}

static void host_processor_observer_mock_on_active_mode (struct host_processor_observer *observer)
{
	struct host_processor_observer_mock *mock = (struct host_processor_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, host_processor_observer_mock_on_active_mode, observer);
}

static void host_processor_observer_mock_on_recovery (struct host_processor_observer *observer)
{
	struct host_processor_observer_mock *mock = (struct host_processor_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, host_processor_observer_mock_on_recovery, observer);
}

static int host_processor_observer_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* host_processor_observer_mock_func_name_map (void *func)
{
	if (func == host_processor_observer_mock_on_soft_reset) {
		return "on_soft_reset";
	}
	else if (func == host_processor_observer_mock_on_bypass_mode) {
		return "on_bypass_mode";
	}
	else if (func == host_processor_observer_mock_on_active_mode) {
		return "on_active_mode";
	}
	else if (func == host_processor_observer_mock_on_recovery) {
		return "on_recovery";
	}
	else {
		return "unknown";
	}
}

static const char* host_processor_observer_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize a mock for receiving host processor notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int host_processor_observer_mock_init (struct host_processor_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct host_processor_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "host_processor_observer");

	mock->base.on_soft_reset = host_processor_observer_mock_on_soft_reset;
	mock->base.on_bypass_mode = host_processor_observer_mock_on_bypass_mode;
	mock->base.on_active_mode = host_processor_observer_mock_on_active_mode;
	mock->base.on_recovery = host_processor_observer_mock_on_recovery;

	mock->mock.func_arg_count = host_processor_observer_mock_func_arg_count;
	mock->mock.func_name_map = host_processor_observer_mock_func_name_map;
	mock->mock.arg_name_map = host_processor_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a host processor observer mock.
 *
 * @param mock The mock to release.
 */
void host_processor_observer_mock_release (struct host_processor_observer_mock *mock)
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
int host_processor_observer_mock_validate_and_release (struct host_processor_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		host_processor_observer_mock_release (mock);
	}

	return status;
}
