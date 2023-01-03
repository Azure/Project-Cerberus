// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_cmd_handler_mock.h"


int manifest_cmd_handler_mock_activation (const struct manifest_cmd_handler *handler, bool *reset)
{
	struct manifest_cmd_handler_mock *mock = (struct manifest_cmd_handler_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_cmd_handler_mock_activation, handler,
		MOCK_ARG_PTR_CALL (reset));
}

static int manifest_cmd_handler_mock_func_arg_count (void *func)
{
	if (func == manifest_cmd_handler_mock_activation) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* manifest_cmd_handler_mock_func_name_map (void *func)
{
	if (func == manifest_cmd_handler_mock_activation) {
		return "activation";
	}
	else {
		return "unknown";
	}
}

static const char* manifest_cmd_handler_mock_arg_name_map (void *func, int arg)
{
	if (func == manifest_cmd_handler_mock_activation) {
		switch (arg) {
			case 0:
				return "reset";
		}
	}

	return "unknown";
}

/**
 * Initialize mock manifest handler.
 *
 * @param mock The mock instance to initialize.
 * @param state Variable context for the handler.  This must be uninitialized.
 * @param manifest The manifest manager to use during command processing.
 * @param task The task that will be used to execute manifest operations.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int manifest_cmd_handler_mock_init (struct manifest_cmd_handler_mock *mock,
	struct manifest_cmd_handler_state *state, const struct manifest_manager *manifest,
	const struct event_task *task)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct manifest_cmd_handler_mock));

	status = manifest_cmd_handler_init (&mock->base, state, manifest, task);
	if (status != 0) {
		return status;
	}

	status = mock_init (&mock->mock);
	if (status != 0) {
		manifest_cmd_handler_release (&mock->base);
		return status;
	}

	mock_set_name (&mock->mock, "manifest_cmd_handler");

	mock->mock.func_arg_count = manifest_cmd_handler_mock_func_arg_count;
	mock->mock.func_name_map = manifest_cmd_handler_mock_func_name_map;
	mock->mock.arg_name_map = manifest_cmd_handler_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock manifest handler.
 *
 * @param mock The mock instance to release.
 */
void manifest_cmd_handler_mock_release (struct manifest_cmd_handler_mock *mock)
{
	if (mock != NULL) {
		manifest_cmd_handler_release (&mock->base);
		mock_release (&mock->mock);
	}
}

/**
 * Verify that a mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int manifest_cmd_handler_mock_validate_and_release (struct manifest_cmd_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		manifest_cmd_handler_mock_release (mock);
	}

	return status;
}

/**
 * Enable the internal hook for activation.
 *
 * @param mock The mock to update.
 */
void manifest_cmd_handler_mock_enable_activation (struct manifest_cmd_handler_mock *mock)
{
	if (mock) {
		mock->base.activation = manifest_cmd_handler_mock_activation;
	}
}
