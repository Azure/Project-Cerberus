// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pcd_observer_mock.h"


static void pcd_observer_mock_on_pcd_activated (struct pcd_observer *observer, struct pcd *active)
{
	struct pcd_observer_mock *mock = (struct pcd_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pcd_observer_mock_on_pcd_activated, observer,
		MOCK_ARG_CALL (active));
}

static void pcd_observer_mock_on_pcd_verified (struct pcd_observer *observer, struct pcd *pending)
{
	struct pcd_observer_mock *mock = (struct pcd_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pcd_observer_mock_on_pcd_verified, observer,
		MOCK_ARG_CALL (pending));
}

static void pcd_observer_mock_on_clear_active (struct pcd_observer *observer)
{
	struct pcd_observer_mock *mock = (struct pcd_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, pcd_observer_mock_on_clear_active, observer);
}

static int pcd_observer_mock_func_arg_count (void *func)
{
	if ((func == pcd_observer_mock_on_pcd_activated) ||
		(func == pcd_observer_mock_on_pcd_verified)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* pcd_observer_mock_func_name_map (void *func)
{
	if (func == pcd_observer_mock_on_pcd_activated) {
		return "on_pcd_activated";
	}
	else if (func == pcd_observer_mock_on_pcd_verified) {
		return "on_pcd_verified";
	}
	else if (func == pcd_observer_mock_on_clear_active) {
		return "on_clear_active";
	}
	else {
		return "unknown";
	}
}

static const char* pcd_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == pcd_observer_mock_on_pcd_activated) {
		switch (arg) {
			case 0:
				return "active";
		}
	}
	else if (func == pcd_observer_mock_on_pcd_verified) {
		switch (arg) {
			case 0:
				return "pending";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for receiving PCD management notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int pcd_observer_mock_init (struct pcd_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct pcd_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "pcd_manager_observer");

	mock->base.on_pcd_activated = pcd_observer_mock_on_pcd_activated;
	mock->base.on_pcd_verified = pcd_observer_mock_on_pcd_verified;
	mock->base.on_clear_active = pcd_observer_mock_on_clear_active;

	mock->mock.func_arg_count = pcd_observer_mock_func_arg_count;
	mock->mock.func_name_map = pcd_observer_mock_func_name_map;
	mock->mock.arg_name_map = pcd_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a PCD observer mock.
 *
 * @param mock The mock to release.
 */
void pcd_observer_mock_release (struct pcd_observer_mock *mock)
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
int pcd_observer_mock_validate_and_release (struct pcd_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		pcd_observer_mock_release (mock);
	}

	return status;
}
