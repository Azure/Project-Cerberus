// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firmware_update_observer_mock.h"


static void firmware_update_observer_mock_on_update_start (
	struct firmware_update_observer *observer, int *update_allowed)
{
	struct firmware_update_observer_mock *mock = (struct firmware_update_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, firmware_update_observer_mock_on_update_start, observer,
		MOCK_ARG_CALL (update_allowed));
}

static int firmware_update_observer_mock_func_arg_count (void *func)
{
	if (func == firmware_update_observer_mock_on_update_start) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* firmware_update_observer_mock_func_name_map (void *func)
{
	if (func == firmware_update_observer_mock_on_update_start) {
		return "on_update_start";
	}
	else {
		return "unknown";
	}
}

static const char* firmware_update_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == firmware_update_observer_mock_on_update_start) {
		switch (arg) {
			case 0:
				return "update_allowed";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for receiving firmware update notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int firmware_update_observer_mock_init (struct firmware_update_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct firmware_update_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "firmware_update_observer");

	mock->base.on_update_start = firmware_update_observer_mock_on_update_start;

	mock->mock.func_arg_count = firmware_update_observer_mock_func_arg_count;
	mock->mock.func_name_map = firmware_update_observer_mock_func_name_map;
	mock->mock.arg_name_map = firmware_update_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a firmware update observer mock.
 *
 * @param mock The mock to release.
 */
void firmware_update_observer_mock_release (struct firmware_update_observer_mock *mock)
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
int firmware_update_observer_mock_validate_and_release (struct firmware_update_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		firmware_update_observer_mock_release (mock);
	}

	return status;
}
