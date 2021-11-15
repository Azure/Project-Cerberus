// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_control_mock.h"


static int host_control_mock_hold_processor_in_reset (struct host_control *control,
	bool reset)
{
	struct host_control_mock *mock = (struct host_control_mock*) control;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_control_mock_hold_processor_in_reset, control,
		MOCK_ARG_CALL (reset));
}

static int host_control_mock_is_processor_held_in_reset (struct host_control *control)
{
	struct host_control_mock *mock = (struct host_control_mock*) control;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_control_mock_is_processor_held_in_reset, control);
}

static int host_control_mock_is_processor_in_reset (struct host_control *control)
{
	struct host_control_mock *mock = (struct host_control_mock*) control;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_control_mock_is_processor_in_reset, control);
}

static int host_control_mock_enable_processor_flash_access (struct host_control *control,
	bool enable)
{
	struct host_control_mock *mock = (struct host_control_mock*) control;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_control_mock_enable_processor_flash_access, control,
		MOCK_ARG_CALL (enable));
}

static int host_control_mock_processor_has_flash_access (struct host_control *control)
{
	struct host_control_mock *mock = (struct host_control_mock*) control;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_control_mock_processor_has_flash_access, control);
}

static int host_control_mock_func_arg_count (void *func)
{
	if ((func == host_control_mock_hold_processor_in_reset) ||
		(func == host_control_mock_enable_processor_flash_access)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* host_control_mock_func_name_map (void *func)
{
	if (func == host_control_mock_hold_processor_in_reset) {
		return "hold_processor_in_reset";
	}
	else if (func == host_control_mock_is_processor_held_in_reset) {
		return "is_processor_held_in_reset";
	}
	else if (func == host_control_mock_is_processor_in_reset) {
		return "is_processor_in_reset";
	}
	else if (func == host_control_mock_enable_processor_flash_access) {
		return "enable_processor_flash_access";
	}
	else if (func == host_control_mock_processor_has_flash_access) {
		return "processor_has_flash_access";
	}
	else {
		return "unknown";
	}
}

static const char* host_control_mock_arg_name_map (void *func, int arg)
{
	if (func == host_control_mock_hold_processor_in_reset) {
		switch (arg) {
			case 0:
				return "reset";
		}
	}
	else if (func == host_control_mock_enable_processor_flash_access) {
		switch (arg) {
			case 0:
				return "enable";
		}
	}

	return "unknown";
}

/**
 * Initialize the mock instance for the processor control API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int host_control_mock_init (struct host_control_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct host_control_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "host_control");

	mock->base.hold_processor_in_reset = host_control_mock_hold_processor_in_reset;
	mock->base.is_processor_held_in_reset = host_control_mock_is_processor_held_in_reset;
	mock->base.is_processor_in_reset = host_control_mock_is_processor_in_reset;
	mock->base.enable_processor_flash_access = host_control_mock_enable_processor_flash_access;
	mock->base.processor_has_flash_access = host_control_mock_processor_has_flash_access;

	mock->mock.func_arg_count = host_control_mock_func_arg_count;
	mock->mock.func_name_map = host_control_mock_func_name_map;
	mock->mock.arg_name_map = host_control_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by the mock API.
 *
 * @param mock The mock to release.
 */
void host_control_mock_release (struct host_control_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate all mock expectations were called and released the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int host_control_mock_validate_and_release (struct host_control_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		host_control_mock_release (mock);
	}

	return status;
}
