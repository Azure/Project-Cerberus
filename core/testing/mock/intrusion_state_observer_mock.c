// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "intrusion_state_observer_mock.h"


static void intrusion_state_observer_mock_on_intrusion (struct intrusion_state_observer *observer)
{
	struct intrusion_state_observer_mock *mock = (struct intrusion_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, intrusion_state_observer_mock_on_intrusion, observer);
}

static void intrusion_state_observer_mock_on_no_intrusion (
	struct intrusion_state_observer *observer)
{
	struct intrusion_state_observer_mock *mock = (struct intrusion_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, intrusion_state_observer_mock_on_no_intrusion, observer);
}

static void intrusion_state_observer_mock_on_error (struct intrusion_state_observer *observer)
{
	struct intrusion_state_observer_mock *mock = (struct intrusion_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, intrusion_state_observer_mock_on_error, observer);
}

static int intrusion_state_observer_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* intrusion_state_observer_mock_func_name_map (void *func)
{
	if (func == intrusion_state_observer_mock_on_intrusion) {
		return "on_intrusion";
	}
	else if (func == intrusion_state_observer_mock_on_no_intrusion) {
		return "on_no_intrusion";
	}
	else if (func == intrusion_state_observer_mock_on_error) {
		return "on_error";
	}
	else {
		return "unknown";
	}
}

static const char* intrusion_state_observer_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize a mock for receiving intrusion state notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int intrusion_state_observer_mock_init (struct intrusion_state_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct intrusion_state_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "intrusion_state_observer");

	mock->base.on_intrusion = intrusion_state_observer_mock_on_intrusion;
	mock->base.on_no_intrusion = intrusion_state_observer_mock_on_no_intrusion;
	mock->base.on_error = intrusion_state_observer_mock_on_error;

	mock->mock.func_arg_count = intrusion_state_observer_mock_func_arg_count;
	mock->mock.func_name_map = intrusion_state_observer_mock_func_name_map;
	mock->mock.arg_name_map = intrusion_state_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by an intrusion state observer mock.
 *
 * @param mock The mock to release.
 */
void intrusion_state_observer_mock_release (struct intrusion_state_observer_mock *mock)
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
int intrusion_state_observer_mock_validate_and_release (struct intrusion_state_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		intrusion_state_observer_mock_release (mock);
	}

	return status;
}
