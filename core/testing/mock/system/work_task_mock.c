// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "work_task_mock.h"


static int work_task_mock_submit (const struct work_task_interface *task,
	struct work_task_entry *entry, const struct work_task_handler *handler, void *context)
{
	struct work_task_mock *mock = (struct work_task_mock*) task;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, work_task_mock_submit, task, MOCK_ARG_PTR_CALL (entry),
		MOCK_ARG_PTR_CALL (handler), MOCK_ARG_PTR_CALL (context));
}

static int work_task_mock_schedule (const struct work_task_interface *task,
	struct work_task_entry *entry, const struct work_task_handler *handler, void *context,
	const platform_clock *next_execution)
{
	struct work_task_mock *mock = (struct work_task_mock*) task;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, work_task_mock_schedule, task, MOCK_ARG_PTR_CALL (entry),
		MOCK_ARG_PTR_CALL (handler), MOCK_ARG_PTR_CALL (context),
		MOCK_ARG_PTR_CALL (next_execution));
}

static int work_task_mock_cancel (const struct work_task_interface *task,
	struct work_task_entry *entry)
{
	struct work_task_mock *mock = (struct work_task_mock*) task;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, work_task_mock_cancel, task, MOCK_ARG_PTR_CALL (entry));
}

static int work_task_mock_func_arg_count (void *func)
{
	if (func == work_task_mock_submit) {
		return 3;
	}
	else if (func == work_task_mock_schedule) {
		return 4;
	}
	else if (func == work_task_mock_cancel) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* work_task_mock_func_name_map (void *func)
{
	if (func == work_task_mock_submit) {
		return "submit";
	}
	else if (func == work_task_mock_schedule) {
		return "schedule";
	}
	else if (func == work_task_mock_cancel) {
		return "cancel";
	}
	else {
		return "unknown";
	}
}

static const char* work_task_mock_arg_name_map (void *func, int arg)
{
	if (func == work_task_mock_submit) {
		switch (arg) {
			case 0:
				return "entry";

			case 1:
				return "handler";

			case 2:
				return "context";
		}
	}
	else if (func == work_task_mock_schedule) {
		switch (arg) {
			case 0:
				return "entry";

			case 1:
				return "handler";

			case 2:
				return "context";

			case 3:
				return "next_execution";
		}
	}
	else if (func == work_task_mock_cancel) {
		switch (arg) {
			case 0:
				return "entry";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a work task.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int work_task_mock_init (struct work_task_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct work_task_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "work_task_interface");

	mock->base.submit = work_task_mock_submit;
	mock->base.schedule = work_task_mock_schedule;
	mock->base.cancel = work_task_mock_cancel;

	mock->mock.func_arg_count = work_task_mock_func_arg_count;
	mock->mock.func_name_map = work_task_mock_func_name_map;
	mock->mock.arg_name_map = work_task_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a work task mock.
 *
 * @param mock The mock to release.
 */
void work_task_mock_release (struct work_task_mock *mock)
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
int work_task_mock_validate_and_release (struct work_task_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		work_task_mock_release (mock);
	}

	return status;
}
