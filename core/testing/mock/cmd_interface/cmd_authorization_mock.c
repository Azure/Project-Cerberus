// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "cmd_authorization_mock.h"


static int cmd_authorization_mock_authorize_revert_bypass (struct cmd_authorization *auth,
	uint8_t **token, size_t *length)
{
	struct cmd_authorization_mock *mock = (struct cmd_authorization_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_authorization_mock_authorize_revert_bypass, auth,
		MOCK_ARG_CALL (token), MOCK_ARG_CALL (length));
}

static int cmd_authorization_mock_authorize_reset_defaults (struct cmd_authorization *auth,
	uint8_t **token, size_t *length)
{
	struct cmd_authorization_mock *mock = (struct cmd_authorization_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_authorization_mock_authorize_reset_defaults, auth,
		MOCK_ARG_CALL (token), MOCK_ARG_CALL (length));
}

static int cmd_authorization_mock_authorize_clear_platform_config (struct cmd_authorization *auth,
	uint8_t **token, size_t *length)
{
	struct cmd_authorization_mock *mock = (struct cmd_authorization_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_authorization_mock_authorize_clear_platform_config, auth,
		MOCK_ARG_CALL (token), MOCK_ARG_CALL (length));
}

static int cmd_authorization_mock_authorize_reset_intrusion (struct cmd_authorization *auth,
	uint8_t **token, size_t *length)
{
	struct cmd_authorization_mock *mock = (struct cmd_authorization_mock*) auth;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_authorization_mock_authorize_reset_intrusion, auth,
		MOCK_ARG_CALL (token), MOCK_ARG_CALL (length));
}

static int cmd_authorization_mock_func_arg_count (void *func)
{
	if ((func == cmd_authorization_mock_authorize_revert_bypass) ||
		(func == cmd_authorization_mock_authorize_reset_defaults) ||
		(func == cmd_authorization_mock_authorize_clear_platform_config) ||
		(func == cmd_authorization_mock_authorize_reset_intrusion)) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* cmd_authorization_mock_func_name_map (void *func)
{
	if (func == cmd_authorization_mock_authorize_revert_bypass) {
		return "authorize_revert_bypass";
	}
	else if (func == cmd_authorization_mock_authorize_reset_defaults) {
		return "authorize_reset_defaults";
	}
	else if (func == cmd_authorization_mock_authorize_clear_platform_config) {
		return "authorize_clear_platform_config";
	}
	else if (func == cmd_authorization_mock_authorize_reset_intrusion) {
		return "authorize_reset_intrusion";
	}
	else {
		return "unknown";
	}
}

static const char* cmd_authorization_mock_arg_name_map (void *func, int arg)
{
	if (func == cmd_authorization_mock_authorize_revert_bypass) {
		switch (arg) {
			case 0:
				return "token";

			case 1:
				return "length";

		}
	}
	else if (func == cmd_authorization_mock_authorize_reset_defaults) {
		switch (arg) {
			case 0:
				return "token";

			case 1:
				return "length";

		}
	}
	else if (func == cmd_authorization_mock_authorize_clear_platform_config) {
		switch (arg) {
			case 0:
				return "token";

			case 1:
				return "length";

		}
	}
	else if (func == cmd_authorization_mock_authorize_reset_intrusion) {
		switch (arg) {
			case 0:
				return "token";

			case 1:
				return "length";

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

	mock->base.authorize_revert_bypass = cmd_authorization_mock_authorize_revert_bypass;
	mock->base.authorize_reset_defaults = cmd_authorization_mock_authorize_reset_defaults;
	mock->base.authorize_clear_platform_config =
		cmd_authorization_mock_authorize_clear_platform_config;
	mock->base.authorize_reset_intrusion = cmd_authorization_mock_authorize_reset_intrusion;

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
