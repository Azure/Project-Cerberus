// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "periodic_task_handler_mock.h"


static void periodic_task_handler_mock_prepare (const struct periodic_task_handler *handler)
{
	struct periodic_task_handler_mock *mock = (struct periodic_task_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, periodic_task_handler_mock_prepare, handler);
}

static const platform_clock* periodic_task_handler_mock_get_next_execution (
	const struct periodic_task_handler *handler)
{
	struct periodic_task_handler_mock *mock = (struct periodic_task_handler_mock*) handler;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, const platform_clock*,
		periodic_task_handler_mock_get_next_execution, handler);
}

static void periodic_task_handler_mock_execute (const struct periodic_task_handler *handler)
{
	struct periodic_task_handler_mock *mock = (struct periodic_task_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, periodic_task_handler_mock_execute, handler);
}

static int periodic_task_handler_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* periodic_task_handler_mock_func_name_map (void *func)
{
	if (func == periodic_task_handler_mock_prepare) {
		return "prepare";
	}
	else if (func == periodic_task_handler_mock_get_next_execution) {
		return "get_next_execution";
	}
	else if (func == periodic_task_handler_mock_execute) {
		return "execute";
	}
	else {
		return "unknown";
	}
}

static const char* periodic_task_handler_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize a mock for an event handler.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int periodic_task_handler_mock_init (struct periodic_task_handler_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct periodic_task_handler_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "periodic_task_handler");

	mock->base.prepare = periodic_task_handler_mock_prepare;
	mock->base.get_next_execution = periodic_task_handler_mock_get_next_execution;
	mock->base.execute = periodic_task_handler_mock_execute;

	mock->mock.func_arg_count = periodic_task_handler_mock_func_arg_count;
	mock->mock.func_name_map = periodic_task_handler_mock_func_name_map;
	mock->mock.arg_name_map = periodic_task_handler_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by an event handler mock.
 *
 * @param mock The mock to release.
 */
void periodic_task_handler_mock_release (struct periodic_task_handler_mock *mock)
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
int periodic_task_handler_mock_validate_and_release (struct periodic_task_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		periodic_task_handler_mock_release (mock);
	}

	return status;
}
