// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_irq_control_mock.h"


static int host_irq_control_mock_enable_exit_reset (struct host_irq_control *control, bool enable)
{
	struct host_irq_control_mock *mock = (struct host_irq_control_mock*) control;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_irq_control_mock_enable_exit_reset, control,
		MOCK_ARG_CALL (enable));
}

static int host_irq_control_mock_enable_chip_selects (struct host_irq_control *control, bool enable)
{
	struct host_irq_control_mock *mock = (struct host_irq_control_mock*) control;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_irq_control_mock_enable_chip_selects, control,
		MOCK_ARG_CALL (enable));
}

static void host_irq_control_mock_enable_notifications (struct host_irq_control *control,
	bool enable)
{
	struct host_irq_control_mock *mock = (struct host_irq_control_mock*) control;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_irq_control_mock_enable_notifications, control,
		MOCK_ARG_CALL (enable));
}

static int host_irq_control_mock_func_arg_count (void *func)
{
	if ((func == host_irq_control_mock_enable_exit_reset) ||
		(func == host_irq_control_mock_enable_chip_selects) ||
		(func == host_irq_control_mock_enable_notifications)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* host_irq_control_mock_func_name_map (void *func)
{
	if (func == host_irq_control_mock_enable_exit_reset) {
		return "enable_exit_reset";
	}
	else if (func == host_irq_control_mock_enable_chip_selects) {
		return "enable_chip_selects";
	}
	else if (func == host_irq_control_mock_enable_notifications) {
		return "enable_notifications";
	}
	else {
		return "unknown";
	}
}

static const char* host_irq_control_mock_arg_name_map (void *func, int arg)
{
	if (func == host_irq_control_mock_enable_exit_reset) {
		switch (arg) {
			case 0:
				return "enable";
		}
	}
	else if (func == host_irq_control_mock_enable_chip_selects) {
		switch (arg) {
			case 0:
				return "enable";
		}
	}
	else if (func == host_irq_control_mock_enable_notifications) {
		switch (arg) {
			case 0:
				return "enable";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock API for host IRQ control.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int host_irq_control_mock_init (struct host_irq_control_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct host_irq_control_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "host_irq_control");

	mock->base.enable_exit_reset = host_irq_control_mock_enable_exit_reset;
	mock->base.enable_chip_selects = host_irq_control_mock_enable_chip_selects;
	mock->base.enable_notifications = host_irq_control_mock_enable_notifications;

	mock->mock.func_arg_count = host_irq_control_mock_func_arg_count;
	mock->mock.func_name_map = host_irq_control_mock_func_name_map;
	mock->mock.arg_name_map = host_irq_control_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock IRQ control API.
 *
 * @param mock The mock to release.
 */
void host_irq_control_mock_release (struct host_irq_control_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify that a mock API was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int host_irq_control_mock_validate_and_release (struct host_irq_control_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		host_irq_control_mock_release (mock);
	}

	return status;
}
