// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "recovery_image_observer_mock.h"


static void recovery_image_observer_mock_on_recovery_image_activated (
	struct recovery_image_observer *observer, struct recovery_image *active)
{
	struct recovery_image_observer_mock *mock = (struct recovery_image_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, recovery_image_observer_mock_on_recovery_image_activated, observer,
		MOCK_ARG_CALL (active));
}

static void recovery_image_observer_mock_on_recovery_image_deactivated (
	struct recovery_image_observer *observer)
{
	struct recovery_image_observer_mock *mock = (struct recovery_image_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock,
		recovery_image_observer_mock_on_recovery_image_deactivated, observer);
}

static int recovery_image_observer_mock_func_arg_count (void *func)
{
	if (func == recovery_image_observer_mock_on_recovery_image_activated) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* recovery_image_observer_mock_func_name_map (void *func)
{
	if (func == recovery_image_observer_mock_on_recovery_image_activated) {
		return "on_recovery_image_activated";
	}
	else if (func == recovery_image_observer_mock_on_recovery_image_deactivated) {
		return "on_recovery_image_deactivated";
	}
	else {
		return "unknown";
	}
}

static const char* recovery_image_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == recovery_image_observer_mock_on_recovery_image_activated) {
		switch (arg) {
			case 0:
				return "active";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for notifying observers of recovery image events.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int recovery_image_observer_mock_init (struct recovery_image_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct recovery_image_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "recovery_image_observer");

	mock->base.on_recovery_image_activated = recovery_image_observer_mock_on_recovery_image_activated;
	mock->base.on_recovery_image_deactivated = recovery_image_observer_mock_on_recovery_image_deactivated;

	mock->mock.func_arg_count = recovery_image_observer_mock_func_arg_count;
	mock->mock.func_name_map = recovery_image_observer_mock_func_name_map;
	mock->mock.arg_name_map = recovery_image_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a recovery image observer mock.
 *
 * @param mock The mock to release.
 */
void recovery_image_observer_mock_release (struct recovery_image_observer_mock *mock)
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
int recovery_image_observer_mock_validate_and_release (struct recovery_image_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		recovery_image_observer_mock_release (mock);
	}

	return status;
}
