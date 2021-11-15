// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "intrusion_manager_mock.h"


static int intrusion_manager_mock_handle_intrusion (struct intrusion_manager *manager)
{
	struct intrusion_manager_mock *mock = (struct intrusion_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, intrusion_manager_mock_handle_intrusion, manager);
}

static int intrusion_manager_mock_reset_intrusion (struct intrusion_manager *manager)
{
	struct intrusion_manager_mock *mock = (struct intrusion_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, intrusion_manager_mock_reset_intrusion, manager);
}

static int intrusion_manager_mock_check_state (struct intrusion_manager *manager)
{
	struct intrusion_manager_mock *mock = (struct intrusion_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, intrusion_manager_mock_check_state, manager);
}

static int intrusion_manager_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* intrusion_manager_mock_func_name_map (void *func)
{
	if (func == intrusion_manager_mock_handle_intrusion) {
		return "handle_intrusion";
	}
	else if (func == intrusion_manager_mock_reset_intrusion) {
		return "reset_intrusion";
	}
	else if (func == intrusion_manager_mock_check_state) {
		return "check_state";
	}
	else {
		return "unknown";
	}
}

static const char* intrusion_manager_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize the mock instance for intrusion management.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int intrusion_manager_mock_init (struct intrusion_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct intrusion_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "intrusion_manager");

	mock->base.handle_intrusion = intrusion_manager_mock_handle_intrusion;
	mock->base.reset_intrusion = intrusion_manager_mock_reset_intrusion;
	mock->base.check_state = intrusion_manager_mock_check_state;

	mock->mock.func_arg_count = intrusion_manager_mock_func_arg_count;
	mock->mock.func_name_map = intrusion_manager_mock_func_name_map;
	mock->mock.arg_name_map = intrusion_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a intrusion management mock.
 *
 * @param mock The mock to release.
 */
void intrusion_manager_mock_release (struct intrusion_manager_mock *mock)
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
int intrusion_manager_mock_validate_and_release (struct intrusion_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		intrusion_manager_mock_release (mock);
	}

	return status;
}
