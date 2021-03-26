// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "pfm_observer_mock.h"


static void pfm_observer_mock_on_pfm_verified (struct pfm_observer *observer,
	struct pfm *pending)
{
	struct pfm_observer_mock *mock = (struct pfm_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pfm_observer_mock_on_pfm_verified, observer,
		MOCK_ARG_CALL (pending));
}

static void pfm_observer_mock_on_pfm_activated (struct pfm_observer *observer,
	struct pfm *active)
{
	struct pfm_observer_mock *mock = (struct pfm_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, pfm_observer_mock_on_pfm_activated, observer,
		MOCK_ARG_CALL (active));
}

static void pfm_observer_mock_on_clear_active (struct pfm_observer *observer)
{
	struct pfm_observer_mock *mock = (struct pfm_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, pfm_observer_mock_on_clear_active, observer);
}

static int pfm_observer_mock_func_arg_count (void *func)
{
	if ((func == pfm_observer_mock_on_pfm_verified) ||
		(func == pfm_observer_mock_on_pfm_activated)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* pfm_observer_mock_func_name_map (void *func)
{
	if (func == pfm_observer_mock_on_pfm_verified) {
		return "on_pfm_verified";
	}
	else if (func == pfm_observer_mock_on_pfm_activated) {
		return "on_pfm_activated";
	}
	else if (func == pfm_observer_mock_on_clear_active) {
		return "on_clear_active";
	}
	else {
		return "unknown";
	}
}

static const char* pfm_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == pfm_observer_mock_on_pfm_verified) {
		switch (arg) {
			case 0:
				return "pending";
		}
	}
	else if (func == pfm_observer_mock_on_pfm_activated) {
		switch (arg) {
			case 0:
				return "active";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for receiving PFM management notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int pfm_observer_mock_init (struct pfm_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct pfm_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "pfm_observer");

	mock->base.on_pfm_verified = pfm_observer_mock_on_pfm_verified;
	mock->base.on_pfm_activated = pfm_observer_mock_on_pfm_activated;
	mock->base.on_clear_active = pfm_observer_mock_on_clear_active;

	mock->mock.func_arg_count = pfm_observer_mock_func_arg_count;
	mock->mock.func_name_map = pfm_observer_mock_func_name_map;
	mock->mock.arg_name_map = pfm_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a PFM observer mock.
 *
 * @param mock The mock to release.
 */
void pfm_observer_mock_release (struct pfm_observer_mock *mock)
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
int pfm_observer_mock_validate_and_release (struct pfm_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		pfm_observer_mock_release (mock);
	}

	return status;
}
