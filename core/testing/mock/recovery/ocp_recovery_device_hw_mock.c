// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ocp_recovery_device_hw_mock.h"


static int ocp_recovery_device_hw_mock_get_device_id (
	const struct ocp_recovery_device_hw *recovery_hw, struct ocp_recovery_device_id *id)
{
	struct ocp_recovery_device_hw_mock *mock = (struct ocp_recovery_device_hw_mock*) recovery_hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ocp_recovery_device_hw_mock_get_device_id, recovery_hw,
		MOCK_ARG_CALL (id));
}

static void ocp_recovery_device_hw_mock_get_device_status (
	const struct ocp_recovery_device_hw *recovery_hw,
	enum ocp_recovery_device_status_code *status_code,
	enum ocp_recovery_recovery_reason_code *reason_code,
	struct ocp_recovery_device_status_vendor *vendor)
{
	struct ocp_recovery_device_hw_mock *mock = (struct ocp_recovery_device_hw_mock*) recovery_hw;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, ocp_recovery_device_hw_mock_get_device_status, recovery_hw,
		MOCK_ARG_CALL (status_code), MOCK_ARG_CALL (reason_code), MOCK_ARG_CALL (vendor));
}

static void ocp_recovery_device_hw_mock_reset_device (
	const struct ocp_recovery_device_hw *recovery_hw, bool forced_recovery)
{
	struct ocp_recovery_device_hw_mock *mock = (struct ocp_recovery_device_hw_mock*) recovery_hw;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, ocp_recovery_device_hw_mock_reset_device, recovery_hw,
		MOCK_ARG_CALL (forced_recovery));
}

static void ocp_recovery_device_hw_mock_reset_management (
	const struct ocp_recovery_device_hw *recovery_hw, bool forced_recovery)
{
	struct ocp_recovery_device_hw_mock *mock = (struct ocp_recovery_device_hw_mock*) recovery_hw;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, ocp_recovery_device_hw_mock_reset_management, recovery_hw,
		MOCK_ARG_CALL (forced_recovery));
}

static int ocp_recovery_device_hw_mock_activate_recovery (
	const struct ocp_recovery_device_hw *recovery_hw,
	const struct ocp_recovery_device_cms *recovery, bool *is_auth_error)
{
	struct ocp_recovery_device_hw_mock *mock = (struct ocp_recovery_device_hw_mock*) recovery_hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ocp_recovery_device_hw_mock_activate_recovery, recovery_hw,
		MOCK_ARG_CALL (recovery), MOCK_ARG_CALL (is_auth_error));
}

static int ocp_recovery_device_hw_mock_func_arg_count (void *func)
{
	if (func == ocp_recovery_device_hw_mock_get_device_status) {
		return 3;
	}
	else if (func == ocp_recovery_device_hw_mock_activate_recovery) {
		return 2;
	}
	else if ((func == ocp_recovery_device_hw_mock_get_device_id) ||
		(func == ocp_recovery_device_hw_mock_reset_device) ||
		(func == ocp_recovery_device_hw_mock_reset_management)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* ocp_recovery_device_hw_mock_func_name_map (void *func)
{
	if (func == ocp_recovery_device_hw_mock_get_device_id) {
		return "get_device_id";
	}
	else if (func == ocp_recovery_device_hw_mock_get_device_status) {
		return "get_device_status";
	}
	else if (func == ocp_recovery_device_hw_mock_reset_device) {
		return "reset_device";
	}
	else if (func == ocp_recovery_device_hw_mock_reset_management) {
		return "reset_management";
	}
	else if (func == ocp_recovery_device_hw_mock_activate_recovery) {
		return "activate_recovery";
	}
	else {
		return "unknown";
	}
}

static const char* ocp_recovery_device_hw_mock_arg_name_map (void *func, int arg)
{
	if (func == ocp_recovery_device_hw_mock_get_device_id) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == ocp_recovery_device_hw_mock_get_device_status) {
		switch (arg) {
			case 0:
				return "status_code";

			case 1:
				return "reason_code";

			case 2:
				return "vendor";
		}
	}
	else if (func == ocp_recovery_device_hw_mock_reset_device) {
		switch (arg) {
			case 0:
				return "forced_recovery";
		}
	}
	else if (func == ocp_recovery_device_hw_mock_reset_management) {
		switch (arg) {
			case 0:
				return "forced_recovery";
		}
	}
	else if (func == ocp_recovery_device_hw_mock_activate_recovery) {
		switch (arg) {
			case 0:
				return "recovery";

			case 1:
				return "is_auth_error";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a OCP Recovery HW interface.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int ocp_recovery_device_hw_mock_init (struct ocp_recovery_device_hw_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct ocp_recovery_device_hw_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "ocp_recovery_device_hw");

	mock->base.get_device_id = ocp_recovery_device_hw_mock_get_device_id;
	mock->base.get_device_status = ocp_recovery_device_hw_mock_get_device_status;
	mock->base.reset_device = ocp_recovery_device_hw_mock_reset_device;
	mock->base.reset_management = ocp_recovery_device_hw_mock_reset_management;
	mock->base.activate_recovery = ocp_recovery_device_hw_mock_activate_recovery;

	mock->mock.func_arg_count = ocp_recovery_device_hw_mock_func_arg_count;
	mock->mock.func_name_map = ocp_recovery_device_hw_mock_func_name_map;
	mock->mock.arg_name_map = ocp_recovery_device_hw_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by the mock API.
 *
 * @param mock The mock to release.
 */
void ocp_recovery_device_hw_mock_release (struct ocp_recovery_device_hw_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate all mock expectations were called and release the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int ocp_recovery_device_hw_mock_validate_and_release (struct ocp_recovery_device_hw_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		ocp_recovery_device_hw_mock_release (mock);
	}

	return status;
}
