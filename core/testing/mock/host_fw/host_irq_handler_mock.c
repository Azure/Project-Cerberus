// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_irq_handler_mock.h"


static int host_irq_handler_mock_power_on (struct host_irq_handler *handler, bool allow_unsecure,
	struct hash_engine *hash)
{
	struct host_irq_handler_mock *mock = (struct host_irq_handler_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_irq_handler_mock_power_on, handler,
		MOCK_ARG_CALL (allow_unsecure), MOCK_ARG_CALL (hash));
}

static int host_irq_handler_mock_enter_reset (struct host_irq_handler *handler)
{
	struct host_irq_handler_mock *mock = (struct host_irq_handler_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_irq_handler_mock_enter_reset, handler);
}

static void host_irq_handler_mock_exit_reset (struct host_irq_handler *handler)
{
	struct host_irq_handler_mock *mock = (struct host_irq_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, host_irq_handler_mock_exit_reset, handler);
}

static void host_irq_handler_mock_assert_cs0 (struct host_irq_handler *handler)
{
	struct host_irq_handler_mock *mock = (struct host_irq_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, host_irq_handler_mock_assert_cs0, handler);
}

static int host_irq_handler_mock_assert_cs1 (struct host_irq_handler *handler)
{
	struct host_irq_handler_mock *mock = (struct host_irq_handler_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_irq_handler_mock_assert_cs1, handler);
}

static int host_irq_handler_mock_func_arg_count (void *func)
{
	if (func == host_irq_handler_mock_power_on) {
		return 2;
	}

	return 0;
}

static const char* host_irq_handler_mock_func_name_map (void *func)
{
	if (func == host_irq_handler_mock_power_on) {
		return "power_on";
	}
	else if (func == host_irq_handler_mock_enter_reset) {
		return "enter_reset";
	}
	else if (func == host_irq_handler_mock_exit_reset) {
		return "exit_reset";
	}
	else if (func == host_irq_handler_mock_assert_cs0) {
		return "assert_cs0";
	}
	else if (func == host_irq_handler_mock_assert_cs1) {
		return "assert_cs1";
	}
	else {
		return "unknown";
	}
}

static const char* host_irq_handler_mock_arg_name_map (void *func, int arg)
{
	if (func == host_irq_handler_mock_power_on) {
		switch (arg) {
			case 0:
				return "allow_unsecure";

			case 1:
				return "hash";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the host IRQ handler.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int host_irq_handler_mock_init (struct host_irq_handler_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct host_irq_handler_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "host_irq_handler");

	mock->base.power_on = host_irq_handler_mock_power_on;
	mock->base.enter_reset = host_irq_handler_mock_enter_reset;
	mock->base.exit_reset = host_irq_handler_mock_exit_reset;
	mock->base.assert_cs0 = host_irq_handler_mock_assert_cs0;
	mock->base.assert_cs1 = host_irq_handler_mock_assert_cs1;

	mock->mock.func_arg_count = host_irq_handler_mock_func_arg_count;
	mock->mock.func_name_map = host_irq_handler_mock_func_name_map;
	mock->mock.arg_name_map = host_irq_handler_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock IRQ handler.
 *
 * @param mock The mock to release.
 */
void host_irq_handler_mock_release (struct host_irq_handler_mock *mock)
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
int host_irq_handler_mock_validate_and_release (struct host_irq_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		host_irq_handler_mock_release (mock);
	}

	return status;
}
