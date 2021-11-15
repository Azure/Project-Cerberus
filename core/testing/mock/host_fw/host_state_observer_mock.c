// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "tpm/tpm.h"
#include "host_state_observer_mock.h"


static void host_state_observer_mock_on_active_pfm (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_mock *mock = (struct host_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_state_observer_mock_on_active_pfm, observer,
		MOCK_ARG_CALL (manager));
}

static void host_state_observer_mock_on_read_only_flash (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_mock *mock = (struct host_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_state_observer_mock_on_read_only_flash, observer,
		MOCK_ARG_CALL (manager));
}

static void host_state_observer_mock_on_inactive_dirty (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_mock *mock = (struct host_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_state_observer_mock_on_inactive_dirty, observer,
		MOCK_ARG_CALL (manager));
}

static void host_state_observer_mock_on_active_recovery_image (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_mock *mock = (struct host_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_state_observer_mock_on_active_recovery_image, observer,
		MOCK_ARG_CALL (manager));
}

static void host_state_observer_mock_on_pfm_dirty (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_mock *mock = (struct host_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_state_observer_mock_on_pfm_dirty, observer,
		MOCK_ARG_CALL (manager));
}

static void host_state_observer_mock_on_run_time_validation (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_mock *mock = (struct host_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_state_observer_mock_on_run_time_validation, observer,
		MOCK_ARG_CALL (manager));
}

static void host_state_observer_mock_on_bypass_mode (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_mock *mock = (struct host_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_state_observer_mock_on_bypass_mode, observer,
		MOCK_ARG_CALL (manager));
}

static void host_state_observer_mock_on_unsupported_flash (struct host_state_observer *observer,
	struct host_state_manager *manager)
{
	struct host_state_observer_mock *mock = (struct host_state_observer_mock*) observer;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_state_observer_mock_on_unsupported_flash, observer,
		MOCK_ARG_CALL (manager));
}

static int host_state_observer_mock_func_arg_count (void *func)
{
	if ((func == host_state_observer_mock_on_active_pfm) ||
		(func == host_state_observer_mock_on_read_only_flash) ||
		(func == host_state_observer_mock_on_inactive_dirty) ||
		(func == host_state_observer_mock_on_active_recovery_image) ||
		(func == host_state_observer_mock_on_pfm_dirty) ||
		(func == host_state_observer_mock_on_run_time_validation) ||
		(func == host_state_observer_mock_on_bypass_mode) ||
		(func == host_state_observer_mock_on_unsupported_flash)) {
		return 1;
	}

	return 0;
}

static const char* host_state_observer_mock_func_name_map (void *func)
{
	if (func == host_state_observer_mock_on_active_pfm) {
		return "on_active_pfm";
	}
	else if (func == host_state_observer_mock_on_read_only_flash) {
		return "on_read_only_flash";
	}
	else if (func == host_state_observer_mock_on_inactive_dirty) {
		return "on_inactive_dirty";
	}
	else if (func == host_state_observer_mock_on_active_recovery_image) {
		return "on_active_recovery_image";
	}
	else if (func == host_state_observer_mock_on_pfm_dirty) {
		return  "on_pfm_dirty";
	}
	else if (func == host_state_observer_mock_on_run_time_validation) {
		return "on_run_time_validation";
	}
	else if (func == host_state_observer_mock_on_bypass_mode) {
		return "on_bypass_mode";
	}
	else if (func == host_state_observer_mock_on_unsupported_flash) {
		return "on_unsupported_flash";
	}
	else {
		return "unknown";
	}
}

static const char* host_state_observer_mock_arg_name_map (void *func, int arg)
{
	if (func == host_state_observer_mock_on_active_pfm) {
		switch (arg) {
			case 0:
				return "manager";
		}
	}
	else if (func == host_state_observer_mock_on_read_only_flash) {
		switch (arg) {
			case 0:
				return "manager";
		}
	}
	else if (func == host_state_observer_mock_on_inactive_dirty) {
		switch (arg) {
			case 0:
				return "manager";
		}
	}
	else if (func == host_state_observer_mock_on_active_recovery_image) {
		switch (arg) {
			case 0:
				return "manager";
		}
	}
	else if (func == host_state_observer_mock_on_pfm_dirty) {
		switch (arg) {
			case 0:
				return "manager";
		}
	}
	else if (func == host_state_observer_mock_on_run_time_validation) {
		switch (arg) {
			case 0:
				return "manager";
		}
	}
	else if (func == host_state_observer_mock_on_bypass_mode) {
		switch (arg) {
			case 0:
				return "manager";
		}
	}
	else if (func == host_state_observer_mock_on_unsupported_flash) {
		switch (arg) {
			case 0:
				return "manager";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for receiving host state notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int host_state_observer_mock_init (struct host_state_observer_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct host_state_observer_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "host_state_observer");

	mock->base.on_active_pfm = host_state_observer_mock_on_active_pfm;
	mock->base.on_read_only_flash = host_state_observer_mock_on_read_only_flash;
	mock->base.on_inactive_dirty = host_state_observer_mock_on_inactive_dirty;
	mock->base.on_active_recovery_image = host_state_observer_mock_on_active_recovery_image;
	mock->base.on_pfm_dirty = host_state_observer_mock_on_pfm_dirty;
	mock->base.on_run_time_validation = host_state_observer_mock_on_run_time_validation;
	mock->base.on_bypass_mode = host_state_observer_mock_on_bypass_mode;
	mock->base.on_unsupported_flash = host_state_observer_mock_on_unsupported_flash;

	mock->mock.func_arg_count = host_state_observer_mock_func_arg_count;
	mock->mock.func_name_map = host_state_observer_mock_func_name_map;
	mock->mock.arg_name_map = host_state_observer_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a host state observer mock.
 *
 * @param mock The mock to release.
 */
void host_state_observer_mock_release (struct host_state_observer_mock *mock)
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
int host_state_observer_mock_validate_and_release (struct host_state_observer_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		host_state_observer_mock_release (mock);
	}

	return status;
}
