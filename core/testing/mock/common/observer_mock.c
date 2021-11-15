// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "observer_mock.h"


static void observer_mock_event (struct observer_mock *observer)
{
	if (observer == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&observer->mock, observer_mock_event, observer);
}

static void observer_mock_event_ptr_arg (struct observer_mock *observer, void *arg)
{
	if (observer == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&observer->mock, observer_mock_event_ptr_arg, observer, MOCK_ARG_CALL (arg));
}

static int observer_mock_func_arg_count (void *func)
{
	if (func == observer_mock_event_ptr_arg) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* observer_mock_func_name_map (void *func)
{
	if (func == observer_mock_event) {
		return "event";
	}
	else if (func == observer_mock_event_ptr_arg) {
		return "event_ptr_arg";
	}
	else {
		return "unknown";
	}
}

static const char* observer_mock_arg_name_map (void *func, int arg)
{
	if (func == observer_mock_event_ptr_arg) {
		switch (arg) {
			case 0:
				return "arg";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for receiving notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int observer_mock_init (struct observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "observer");

	mock->event = observer_mock_event;
	mock->event_ptr_arg = observer_mock_event_ptr_arg;

	mock->mock.func_arg_count = observer_mock_func_arg_count;
	mock->mock.func_name_map = observer_mock_func_name_map;
	mock->mock.arg_name_map = observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock observer.
 *
 * @param mock The mock to release.
 */
void observer_mock_release (struct observer_mock *mock)
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
int observer_mock_validate_and_release (struct observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		observer_mock_release (mock);
	}

	return status;
}
