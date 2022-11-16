// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "event_task_mock.h"


static int event_task_mock_lock (const struct event_task *task)
{
	struct event_task_mock *mock = (struct event_task_mock*) task;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, event_task_mock_lock, task);
}

static int event_task_mock_unlock (const struct event_task *task)
{
	struct event_task_mock *mock = (struct event_task_mock*) task;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, event_task_mock_unlock, task);
}

static int event_task_mock_get_event_context (const struct event_task *task,
	struct event_task_context **context)
{
	struct event_task_mock *mock = (struct event_task_mock*) task;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, event_task_mock_get_event_context, task, MOCK_ARG_CALL (context));
}

static int event_task_mock_notify (const struct event_task *task,
	const struct event_task_handler *handler)
{
	struct event_task_mock *mock = (struct event_task_mock*) task;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, event_task_mock_notify, task, MOCK_ARG_CALL (handler));
}

static int event_task_mock_func_arg_count (void *func)
{
	if ((func == event_task_mock_get_event_context) || (func == event_task_mock_notify)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* event_task_mock_func_name_map (void *func)
{
	if (func == event_task_mock_lock) {
		return "lock";
	}
	else if (func == event_task_mock_unlock) {
		return "unlock";
	}
	else if (func == event_task_mock_get_event_context) {
		return "get_event_context";
	}
	else if (func == event_task_mock_notify) {
		return "notify";
	}
	else {
		return "unknown";
	}
}

static const char* event_task_mock_arg_name_map (void *func, int arg)
{
	if (func == event_task_mock_get_event_context) {
		switch (arg) {
			case 0:
				return "context";
		}
	}
	else if (func == event_task_mock_notify) {
		switch (arg) {
			case 0:
				return "handler";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for an event handling task.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int event_task_mock_init (struct event_task_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct event_task_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "event_task");

	mock->base.lock = event_task_mock_lock;
	mock->base.unlock = event_task_mock_unlock;
	mock->base.get_event_context = event_task_mock_get_event_context;
	mock->base.notify = event_task_mock_notify;

	mock->mock.func_arg_count = event_task_mock_func_arg_count;
	mock->mock.func_name_map = event_task_mock_func_name_map;
	mock->mock.arg_name_map = event_task_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by an event task mock.
 *
 * @param mock The mock to release.
 */
void event_task_mock_release (struct event_task_mock *mock)
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
int event_task_mock_validate_and_release (struct event_task_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		event_task_mock_release (mock);
	}

	return status;
}
