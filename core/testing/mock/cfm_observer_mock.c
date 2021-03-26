// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cfm_observer_mock.h"


static void cfm_observer_mock_on_cfm_verified (struct cfm_observer *observer, struct cfm *pending)
{
	struct cfm_observer_mock *mock = (struct cfm_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_observer_mock_on_cfm_verified, observer,
		MOCK_ARG_CALL (pending));
}

static void cfm_observer_mock_on_cfm_activated (struct cfm_observer *observer, struct cfm *active)
{
	struct cfm_observer_mock *mock = (struct cfm_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, cfm_observer_mock_on_cfm_activated, observer,
		MOCK_ARG_CALL (active));
}

static void cfm_observer_mock_on_clear_active (struct cfm_observer *observer)
{
	struct cfm_observer_mock *mock = (struct cfm_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, cfm_observer_mock_on_clear_active, observer);
}

static int cfm_observer_mock_func_arg_count (void *func)
{
	if ((func == cfm_observer_mock_on_cfm_verified) ||
		(func == cfm_observer_mock_on_cfm_activated)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cfm_observer_mock_func_name_map (void *func)
{
	if (func == cfm_observer_mock_on_cfm_verified) {
		return "on_cfm_verified";
	}
	else if (func == cfm_observer_mock_on_cfm_activated) {
		return "on_cfm_activated";
	}
	else if (func == cfm_observer_mock_on_clear_active) {
		return "on_clear_active";
	}
	else {
		return "unknown";
	}
}

static const char* cfm_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == cfm_observer_mock_on_cfm_verified) {
		switch (arg) {
			case 0:
				return "pending";
		}
	}
	else if (func == cfm_observer_mock_on_cfm_activated) {
		switch (arg) {
			case 0:
				return "active";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for receiving CFM management notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int cfm_observer_mock_init (struct cfm_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cfm_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cfm_manager_observer");

	mock->base.on_cfm_verified = cfm_observer_mock_on_cfm_verified;
	mock->base.on_cfm_activated = cfm_observer_mock_on_cfm_activated;
	mock->base.on_clear_active = cfm_observer_mock_on_clear_active;

	mock->mock.func_arg_count = cfm_observer_mock_func_arg_count;
	mock->mock.func_name_map = cfm_observer_mock_func_name_map;
	mock->mock.arg_name_map = cfm_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a CFM observer mock.
 *
 * @param mock The mock to release.
 */
void cfm_observer_mock_release (struct cfm_observer_mock *mock)
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
int cfm_observer_mock_validate_and_release (struct cfm_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cfm_observer_mock_release (mock);
	}

	return status;
}
