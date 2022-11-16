// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "event_task_handler_mock.h"


static void event_task_handler_mock_prepare (const struct event_task_handler *handler)
{
	struct event_task_handler_mock *mock = (struct event_task_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN_NO_ARGS (&mock->mock, event_task_handler_mock_prepare, handler);
}

static void event_task_handler_mock_execute (const struct event_task_handler *handler,
	struct event_task_context *context, bool *reset)
{
	struct event_task_handler_mock *mock = (struct event_task_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, event_task_handler_mock_execute, handler,
		MOCK_ARG_CALL (context), MOCK_ARG_CALL (reset));
}

static int event_task_handler_mock_func_arg_count (void *func)
{
	if (func == event_task_handler_mock_execute) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* event_task_handler_mock_func_name_map (void *func)
{
	if (func == event_task_handler_mock_prepare) {
		return "prepare";
	}
	else if (func == event_task_handler_mock_execute) {
		return "execute";
	}
	else {
		return "unknown";
	}
}

static const char* event_task_handler_mock_arg_name_map (void *func, int arg)
{
	if (func == event_task_handler_mock_execute) {
		switch (arg) {
			case 0:
				return "context";

			case 1:
				return "reset";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for an event handler.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int event_task_handler_mock_init (struct event_task_handler_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct event_task_handler_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "event_task_handler");

	mock->base.prepare = event_task_handler_mock_prepare;
	mock->base.execute = event_task_handler_mock_execute;

	mock->mock.func_arg_count = event_task_handler_mock_func_arg_count;
	mock->mock.func_name_map = event_task_handler_mock_func_name_map;
	mock->mock.arg_name_map = event_task_handler_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by an event handler mock.
 *
 * @param mock The mock to release.
 */
void event_task_handler_mock_release (struct event_task_handler_mock *mock)
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
int event_task_handler_mock_validate_and_release (struct event_task_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		event_task_handler_mock_release (mock);
	}

	return status;
}
