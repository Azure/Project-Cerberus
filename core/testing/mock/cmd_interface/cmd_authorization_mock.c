// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_authorization_mock.h"


static int cmd_authorization_mock_authorize_operation (const struct cmd_authorization *auth,
	uint32_t operation_id, const uint8_t **token, size_t *length,
	const struct authorized_execution **execution)
{
	struct cmd_authorization_mock *mock = (struct cmd_authorization_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_authorization_mock_authorize_operation, auth,
		MOCK_ARG_CALL (operation_id), MOCK_ARG_PTR_CALL (token), MOCK_ARG_PTR_CALL (length),
		MOCK_ARG_PTR_CALL (execution));
}

static int cmd_authorization_mock_func_arg_count (void *func)
{
	if (func == cmd_authorization_mock_authorize_operation) {
		return 4;
	}
	else {
		return 0;
	}
}

static const char* cmd_authorization_mock_func_name_map (void *func)
{
	if (func == cmd_authorization_mock_authorize_operation) {
		return "authorize_operation";
	}
	else {
		return "unknown";
	}
}

static const char* cmd_authorization_mock_arg_name_map (void *func, int arg)
{
	if (func == cmd_authorization_mock_authorize_operation) {
		switch (arg) {
			case 0:
				return "operation_id";

			case 1:
				return "token";

			case 2:
				return "length";

			case 3:
				return "execution";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for handling command authorization.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int cmd_authorization_mock_init (struct cmd_authorization_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cmd_authorization_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cmd_authorization");

	mock->base.authorize_operation = cmd_authorization_mock_authorize_operation;

	mock->mock.func_arg_count = cmd_authorization_mock_func_arg_count;
	mock->mock.func_name_map = cmd_authorization_mock_func_name_map;
	mock->mock.arg_name_map = cmd_authorization_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock command authorization handler.
 *
 * @param mock The mock to release.
 */
void cmd_authorization_mock_release (struct cmd_authorization_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int cmd_authorization_mock_validate_and_release (struct cmd_authorization_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cmd_authorization_mock_release (mock);
	}

	return status;
}
