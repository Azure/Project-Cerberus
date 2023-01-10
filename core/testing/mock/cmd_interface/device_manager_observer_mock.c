// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "status/rot_status.h"
#include "device_manager_observer_mock.h"


static void device_manager_observer_mock_on_set_eid (struct device_manager_observer *observer, int *eid)
{
	struct device_manager_observer_mock *mock = (struct device_manager_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, device_manager_observer_mock_on_set_eid, observer,
		MOCK_ARG_PTR_CALL (eid));
}

static int device_manager_observer_mock_func_arg_count (void *func)
{
	if (func == device_manager_observer_mock_on_set_eid) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* device_manager_observer_mock_func_name_map (void *func)
{
	if (func == device_manager_observer_mock_on_set_eid) {
		return "on_set_eid";
	}
	else {
		return "unknown";
	}
}

static const char* device_manager_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == device_manager_observer_mock_on_set_eid) {
		switch (arg) {
			case 0:
				return "eid";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a device manager observer.
 *
 * @param mock The mock instance to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int device_manager_observer_mock_init (struct device_manager_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct device_manager_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "device_manager_observer");

	mock->base.on_set_eid = device_manager_observer_mock_on_set_eid;

	mock->mock.func_arg_count = device_manager_observer_mock_func_arg_count;
	mock->mock.func_name_map = device_manager_observer_mock_func_name_map;
	mock->mock.arg_name_map = device_manager_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock device manager observer.
 *
 * @param mock The mock instance to release.
 */
void device_manager_observer_mock_release (struct device_manager_observer_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that all mock expectations were executed and release the mock instance.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int device_manager_observer_mock_validate_and_release (struct device_manager_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		device_manager_observer_mock_release (mock);
	}

	return status;
}
