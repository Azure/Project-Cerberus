// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "platform_io.h"
#include "cmd_interface/cmd_interface.h"
#include "pcisig/doe/doe_base_protocol.h"
#include "pcisig/doe/doe_interface.h"
#include "doe_channel_mock.h"


static int doe_cmd_channel_mock_receive_message (
	const struct doe_cmd_channel *channel, struct doe_cmd_message **message, int ms_timeout)
{
	struct doe_cmd_channel_mock *mock = (struct doe_cmd_channel_mock*) channel;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, doe_cmd_channel_mock_receive_message, channel,
		MOCK_ARG_PTR_CALL (message), MOCK_ARG_CALL (ms_timeout));
}

static int doe_cmd_channel_mock_send_message (
	const struct doe_cmd_channel *channel, const struct doe_cmd_message *message)
{
	struct doe_cmd_channel_mock *mock = (struct doe_cmd_channel_mock*) channel;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, doe_cmd_channel_mock_send_message, channel,
		MOCK_ARG_PTR_CALL (message));
}

static int doe_cmd_channel_mock_func_arg_count (void *func)
{
	if (func == doe_cmd_channel_mock_receive_message) {
		return 2;
	}
	else if (func == doe_cmd_channel_mock_send_message) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* doe_cmd_channel_mock_arg_name_map (void *func, int arg)
{
	if (func == doe_cmd_channel_mock_receive_message) {
		switch (arg) {
			case 0:
				return "message";

			case 1:
				return "ms_timeout";
		}
	}
	else if (func == doe_cmd_channel_mock_send_message) {
		switch (arg) {
			case 0:
				return "message";
		}
	}

	return "unknown";
}

static const char* doe_cmd_channel_mock_func_name_map (void *func)
{
	if (func == doe_cmd_channel_mock_receive_message) {
		return "receive_message";
	}
	else if (func == doe_cmd_channel_mock_send_message) {
		return "send_message";
	}
	else {
		return "unknown";
	}	
}

/**
 * Initialize a mock for receiving SPDM protocol notifications.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int doe_cmd_channel_mock_init (struct doe_cmd_channel_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct doe_cmd_channel_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "doe_cmd_channel");

	mock->base.receive_message = doe_cmd_channel_mock_receive_message;
	mock->base.send_message = doe_cmd_channel_mock_send_message;

	mock->mock.func_arg_count = doe_cmd_channel_mock_func_arg_count;
	mock->mock.func_name_map = doe_cmd_channel_mock_func_name_map;
	mock->mock.arg_name_map = doe_cmd_channel_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a doe command channel mock.
 *
 * @param mock The mock to release.
 */
void doe_cmd_channel_mock_release (struct doe_cmd_channel_mock *mock)
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
int doe_cmd_channel_mock_validate_and_release (struct doe_cmd_channel_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		doe_cmd_channel_mock_release (mock);
	}

	return status;
}