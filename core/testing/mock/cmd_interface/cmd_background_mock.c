// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "cmd_background_mock.h"


static int cmd_background_mock_unseal_start (const struct cmd_background *cmd,
	const uint8_t *unseal_request, size_t length)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_background_mock_unseal_start, cmd,
		MOCK_ARG_PTR_CALL (unseal_request), MOCK_ARG_CALL (length));
}

static int cmd_background_mock_unseal_result (const struct cmd_background *cmd, uint8_t *key,
	size_t *key_length, uint32_t *unseal_status)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_background_mock_unseal_result, cmd, MOCK_ARG_PTR_CALL (key),
		MOCK_ARG_PTR_CALL (key_length), MOCK_ARG_PTR_CALL (unseal_status));
}

static int cmd_background_mock_execute_authorized_operation (const struct cmd_background *cmd,
	const struct cmd_authorization_operation_context *op_context)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_background_mock_execute_authorized_operation, cmd,
		MOCK_ARG_PTR_CALL (op_context));
}

static int cmd_background_mock_get_authorized_operation_status (const struct cmd_background *cmd)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cmd_background_mock_get_authorized_operation_status, cmd);
}

static int cmd_background_mock_debug_log_clear (const struct cmd_background *cmd)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cmd_background_mock_debug_log_clear, cmd);
}

static int cmd_background_mock_debug_log_fill (const struct cmd_background *cmd)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cmd_background_mock_debug_log_fill, cmd);
}

static int cmd_background_mock_authenticate_riot_certs (const struct cmd_background *cmd)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cmd_background_mock_authenticate_riot_certs, cmd);
}

static int cmd_background_mock_get_riot_cert_chain_state (const struct cmd_background *cmd)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cmd_background_mock_get_riot_cert_chain_state, cmd);
}

static int cmd_background_mock_reboot_device (const struct cmd_background *cmd)
{
	struct cmd_background_mock *mock = (struct cmd_background_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cmd_background_mock_reboot_device, cmd);
}

static int cmd_background_mock_func_arg_count (void *func)
{
	if (func == cmd_background_mock_unseal_result) {
		return 3;
	}
	else if (func == cmd_background_mock_unseal_start) {
		return 2;
	}
	else if (func == cmd_background_mock_execute_authorized_operation) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cmd_background_mock_func_name_map (void *func)
{
	if (func == cmd_background_mock_unseal_start) {
		return "unseal_start";
	}
	else if (func == cmd_background_mock_unseal_result) {
		return "unseal_result";
	}
	else if (func == cmd_background_mock_execute_authorized_operation) {
		return "execute_authorized_operation";
	}
	else if (func == cmd_background_mock_get_authorized_operation_status) {
		return "get_authorized_operation_status";
	}
	else if (func == cmd_background_mock_debug_log_clear) {
		return "debug_log_clear";
	}
	else if (func == cmd_background_mock_debug_log_fill) {
		return "debug_log_fill";
	}
	else if (func == cmd_background_mock_authenticate_riot_certs) {
		return "authenticate_riot_certs";
	}
	else if (func == cmd_background_mock_get_riot_cert_chain_state) {
		return "get_riot_cert_chain_state";
	}
	else if (func == cmd_background_mock_reboot_device) {
		return "reboot_device";
	}
	else {
		return "unknown";
	}
}

static const char* cmd_background_mock_arg_name_map (void *func, int arg)
{
	if (func == cmd_background_mock_unseal_start) {
		switch (arg) {
			case 0:
				return "unseal_request";

			case 1:
				return "length";
		}
	}
	else if (func == cmd_background_mock_unseal_result) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "key_length";

			case 2:
				return "unseal_status";
		}
	}
	else if (func == cmd_background_mock_execute_authorized_operation) {
		switch (arg) {
			case 0:
				return "op_context";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a command background context.
 *
 * @param mock The mock instance to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int cmd_background_mock_init (struct cmd_background_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cmd_background_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cmd_background");

	mock->base.unseal_start = cmd_background_mock_unseal_start;
	mock->base.unseal_result = cmd_background_mock_unseal_result;
	mock->base.execute_authorized_operation = cmd_background_mock_execute_authorized_operation;
	mock->base.get_authorized_operation_status =
		cmd_background_mock_get_authorized_operation_status;
	mock->base.debug_log_clear = cmd_background_mock_debug_log_clear;
	mock->base.debug_log_fill = cmd_background_mock_debug_log_fill;
	mock->base.authenticate_riot_certs = cmd_background_mock_authenticate_riot_certs;
	mock->base.get_riot_cert_chain_state = cmd_background_mock_get_riot_cert_chain_state;
	mock->base.reboot_device = cmd_background_mock_reboot_device;

	mock->mock.func_arg_count = cmd_background_mock_func_arg_count;
	mock->mock.func_name_map = cmd_background_mock_func_name_map;
	mock->mock.arg_name_map = cmd_background_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock background command context.
 *
 * @param mock The mock instance to release.
 */
void cmd_background_mock_release (struct cmd_background_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that all mock expectations were executed and release the mock instance.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int cmd_background_mock_validate_and_release (struct cmd_background_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cmd_background_mock_release (mock);
	}

	return status;
}
