// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "work_task_handler_mock.h"


static void work_task_handler_mock_execute (const struct work_task_handler *handler,
	const struct work_task_interface *task, void *context)
{
	struct work_task_handler_mock *mock = (struct work_task_handler_mock*) handler;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, work_task_handler_mock_execute, handler,
		MOCK_ARG_PTR_CALL (task), MOCK_ARG_PTR_CALL (context));
}

static int work_task_handler_mock_func_arg_count (void *func)
{
	if (func == work_task_handler_mock_execute) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* work_task_handler_mock_func_name_map (void *func)
{
	if (func == work_task_handler_mock_execute) {
		return "execute";
	}
	else {
		return "unknown";
	}
}

static const char* work_task_handler_mock_arg_name_map (void *func, int arg)
{
	if (func == work_task_handler_mock_execute) {
		switch (arg) {
			case 0:
				return "task";

			case 1:
				return "context";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a work task handler.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int work_task_handler_mock_init (struct work_task_handler_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct work_task_handler_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "work_task_handler");

	mock->base.execute = work_task_handler_mock_execute;

	mock->mock.func_arg_count = work_task_handler_mock_func_arg_count;
	mock->mock.func_name_map = work_task_handler_mock_func_name_map;
	mock->mock.arg_name_map = work_task_handler_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a work task handler mock.
 *
 * @param mock The mock to release.
 */
void work_task_handler_mock_release (struct work_task_handler_mock *mock)
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
int work_task_handler_mock_validate_and_release (struct work_task_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		work_task_handler_mock_release (mock);
	}

	return status;
}
