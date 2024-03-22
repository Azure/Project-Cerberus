// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include <stdint.h>
#include "cmd_interface_protocol_mock.h"


static int cmd_interface_protocol_mock_parse_message (const struct cmd_interface_protocol *protocol,
	struct cmd_interface_msg *message, uint32_t *message_type)
{
	struct cmd_interface_protocol_mock *mock = (struct cmd_interface_protocol_mock*) protocol;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_protocol_mock_parse_message, protocol,
		MOCK_ARG_PTR_CALL (message), MOCK_ARG_PTR_CALL (message_type));
}

static int cmd_interface_protocol_mock_handle_request_result (
	const struct cmd_interface_protocol *protocol, int result, uint32_t message_type,
	struct cmd_interface_msg *message)
{
	struct cmd_interface_protocol_mock *mock = (struct cmd_interface_protocol_mock*) protocol;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_protocol_mock_handle_request_result, protocol,
		MOCK_ARG_CALL (result), MOCK_ARG_CALL (message_type), MOCK_ARG_PTR_CALL (message));
}

static int cmd_interface_protocol_mock_func_arg_count (void *func)
{
	if (func == cmd_interface_protocol_mock_handle_request_result) {
		return 3;
	}
	else if (func == cmd_interface_protocol_mock_parse_message) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* cmd_interface_protocol_mock_func_name_map (void *func)
{
	if (func == cmd_interface_protocol_mock_parse_message) {
		return "get_message_type";
	}
	else if (func == cmd_interface_protocol_mock_handle_request_result) {
		return "handle_request_result";
	}
	else {
		return "unknown";
	}
}

static const char* cmd_interface_protocol_mock_arg_name_map (void *func, int arg)
{
	if (func == cmd_interface_protocol_mock_parse_message) {
		switch (arg) {
			case 0:
				return "message";

			case 1:
				return "message_type";
		}
	}
	else if (func == cmd_interface_protocol_mock_handle_request_result) {
		switch (arg) {
			case 0:
				return "result";

			case 1:
				return "message_type";

			case 2:
				return "message";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a command protocol handler.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int cmd_interface_protocol_mock_init (struct cmd_interface_protocol_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cmd_interface_protocol_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cmd_interface_protocol");

	mock->base.parse_message = cmd_interface_protocol_mock_parse_message;
	mock->base.handle_request_result = cmd_interface_protocol_mock_handle_request_result;

	mock->mock.func_arg_count = cmd_interface_protocol_mock_func_arg_count;
	mock->mock.func_name_map = cmd_interface_protocol_mock_func_name_map;
	mock->mock.arg_name_map = cmd_interface_protocol_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock protocol handler.
 *
 * @param mock The mock to release.
 */
void cmd_interface_protocol_mock_release (struct cmd_interface_protocol_mock *mock)
{
	if (mock != NULL) {
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
int cmd_interface_protocol_mock_validate_and_release (struct cmd_interface_protocol_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cmd_interface_protocol_mock_release (mock);
	}

	return status;
}
