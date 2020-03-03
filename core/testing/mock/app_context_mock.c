// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "app_context_mock.h"


static int app_context_mock_save (struct app_context *context)
{
	struct app_context_mock *mock = (struct app_context_mock*) context;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, app_context_mock_save, context);
}

static int app_context_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* app_context_mock_func_name_map (void *func)
{
	if (func == app_context_mock_save) {
		return "save";
	}
	else {
		return "unknown";
	}
}

static const char* app_context_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize the application context mock API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int app_context_mock_init (struct app_context_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct app_context_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "app_context");

	mock->base.save = app_context_mock_save;

	mock->mock.func_arg_count = app_context_mock_func_arg_count;
	mock->mock.func_name_map = app_context_mock_func_name_map;
	mock->mock.arg_name_map = app_context_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by an application context mock API.
 *
 * @param mock The mock to release.
 */
void app_context_mock_release (struct app_context_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify that all expected mock calls were made and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expected execution occurred or 1 if not.
 */
int app_context_mock_validate_and_release (struct app_context_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		app_context_mock_release (mock);
	}

	return status;
}
