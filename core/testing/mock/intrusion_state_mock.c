// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "intrusion_state_mock.h"


static int intrusion_state_mock_clear (struct intrusion_state *state)
{
	struct intrusion_state_mock *mock = (struct intrusion_state_mock*) state;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, intrusion_state_mock_clear, state);
}

static int intrusion_state_mock_check (struct intrusion_state *state)
{
	struct intrusion_state_mock *mock = (struct intrusion_state_mock*) state;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, intrusion_state_mock_check, state);
}

static int intrusion_state_mock_set (struct intrusion_state *state)
{
	struct intrusion_state_mock *mock = (struct intrusion_state_mock*) state;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, intrusion_state_mock_set, state);
}

static int intrusion_state_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* intrusion_state_mock_func_name_map (void *func)
{
	if (func == intrusion_state_mock_clear) {
		return "clear";
	}
	else if (func == intrusion_state_mock_check) {
		return "check";
	}
	else if (func == intrusion_state_mock_set) {
		return "set";
	}
	else {
		return "unknown";
	}
}

static const char* intrusion_state_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize the mock intrusion state instance.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int intrusion_state_mock_init (struct intrusion_state_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct intrusion_state_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "intrusion_state");

	mock->base.clear = intrusion_state_mock_clear;
	mock->base.check = intrusion_state_mock_check;
	mock->base.set = intrusion_state_mock_set;

	mock->mock.func_arg_count = intrusion_state_mock_func_arg_count;
	mock->mock.func_name_map = intrusion_state_mock_func_name_map;
	mock->mock.arg_name_map = intrusion_state_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by an intrusion state mock.
 *
 * @param mock The mock to release.
 */
void intrusion_state_mock_release (struct intrusion_state_mock *mock)
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
int intrusion_state_mock_validate_and_release (struct intrusion_state_mock *mock)
{
	int status = 0;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		intrusion_state_mock_release (mock);
	}

	return status;
}
