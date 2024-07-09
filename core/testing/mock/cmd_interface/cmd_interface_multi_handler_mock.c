// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "cmd_interface_multi_handler_mock.h"
#include "testing.h"


static int cmd_interface_multi_handler_mock_process_request (const struct cmd_interface *intf,
	struct cmd_interface_msg *request)
{
	struct cmd_interface_multi_handler_mock *mock = (struct cmd_interface_multi_handler_mock*) intf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_multi_handler_mock_process_request, intf,
		MOCK_ARG_PTR_CALL (request));
}

static int cmd_interface_multi_handler_mock_process_response (const struct cmd_interface *intf,
	struct cmd_interface_msg *response)
{
	struct cmd_interface_multi_handler_mock *mock = (struct cmd_interface_multi_handler_mock*) intf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_multi_handler_mock_process_response, intf,
		MOCK_ARG_PTR_CALL (response));
}

static int cmd_interface_multi_handler_mock_is_message_type_supported (
	const struct cmd_interface_multi_handler *intf, uint32_t message_type)
{
	struct cmd_interface_multi_handler_mock *mock = (struct cmd_interface_multi_handler_mock*) intf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_interface_multi_handler_mock_is_message_type_supported, intf,
		MOCK_ARG_CALL (message_type));
}

static int cmd_interface_multi_handler_mock_func_arg_count (void *func)
{
	if ((func == cmd_interface_multi_handler_mock_process_request) ||
		(func == cmd_interface_multi_handler_mock_process_response) ||
		(func == cmd_interface_multi_handler_mock_is_message_type_supported)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cmd_interface_multi_handler_mock_func_name_map (void *func)
{
	if (func == cmd_interface_multi_handler_mock_process_request) {
		return "process_request";
	}
	else if (func == cmd_interface_multi_handler_mock_process_response) {
		return "process_response";
	}
	else if (func == cmd_interface_multi_handler_mock_is_message_type_supported) {
		return "is_message_type_supported";
	}
	else {
		return "unknown";
	}
}

static const char* cmd_interface_multi_handler_mock_arg_name_map (void *func, int arg)
{
	if (func == cmd_interface_multi_handler_mock_process_request) {
		switch (arg) {
			case 0:
				return "request";
		}
	}
	else if (func == cmd_interface_multi_handler_mock_process_response) {
		switch (arg) {
			case 0:
				return "response";
		}
	}
	else if (func == cmd_interface_multi_handler_mock_is_message_type_supported) {
		switch (arg) {
			case 0:
				return "message_type";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a command handler that supports multiple unique message types.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int cmd_interface_multi_handler_mock_init (struct cmd_interface_multi_handler_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cmd_interface_multi_handler_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cmd_interface_multi_handler");

	mock->base.base.process_request = cmd_interface_multi_handler_mock_process_request;
	mock->base.base.process_response = cmd_interface_multi_handler_mock_process_response;

	mock->base.is_message_type_supported =
		cmd_interface_multi_handler_mock_is_message_type_supported;

	mock->mock.func_arg_count = cmd_interface_multi_handler_mock_func_arg_count;
	mock->mock.func_name_map = cmd_interface_multi_handler_mock_func_name_map;
	mock->mock.arg_name_map = cmd_interface_multi_handler_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock multi-message type command handler.
 *
 * @param mock The mock to release.
 */
void cmd_interface_multi_handler_mock_release (struct cmd_interface_multi_handler_mock *mock)
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
int cmd_interface_multi_handler_mock_validate_and_release (
	struct cmd_interface_multi_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cmd_interface_multi_handler_mock_release (mock);
	}

	return status;
}
