// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "cmd_device_mock.h"


static int cmd_device_mock_get_uuid (struct cmd_device *device, uint8_t *buffer, size_t buf_len)
{
	struct cmd_device_mock *mock = (struct cmd_device_mock*) device;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_device_mock_get_uuid, device, MOCK_ARG_CALL (buffer),
		MOCK_ARG_CALL (buf_len));
}

static int cmd_device_mock_reset (struct cmd_device *device)
{
	struct cmd_device_mock *mock = (struct cmd_device_mock*) device;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, cmd_device_mock_reset, device);
}

static int cmd_device_mock_get_reset_counter (struct cmd_device *device, uint8_t type, uint8_t port,
	uint16_t *counter)
{
	struct cmd_device_mock *mock = (struct cmd_device_mock*) device;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_device_mock_get_reset_counter, device, MOCK_ARG_CALL (type),
		MOCK_ARG_CALL (port), MOCK_ARG_CALL (counter));
}

static int cmd_device_mock_get_heap_stats (struct cmd_device *device,
	struct cmd_device_heap_stats *heap)
{
	struct cmd_device_mock *mock = (struct cmd_device_mock*) device;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cmd_device_mock_get_heap_stats, device, MOCK_ARG_CALL (heap));
}

static int cmd_device_mock_func_arg_count (void *func)
{
	if (func == cmd_device_mock_get_reset_counter) {
		return 3;
	}
	else if (func == cmd_device_mock_get_uuid) {
		return 2;
	}
	else if (func == cmd_device_mock_get_heap_stats) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cmd_device_mock_func_name_map (void *func)
{
	if (func == cmd_device_mock_get_uuid) {
		return "get_uuid";
	}
	else if (func == cmd_device_mock_reset) {
		return "reset";
	}
	else if (func == cmd_device_mock_get_reset_counter) {
		return "get_reset_counter";
	}
	else if (func == cmd_device_mock_get_heap_stats) {
		return "get_heap_stats";
	}
	else {
		return "unknown";
	}
}

static const char* cmd_device_mock_arg_name_map (void *func, int arg)
{
	if (func == cmd_device_mock_get_uuid) {
		switch (arg) {
			case 0:
				return "buffer";

			case 1:
				return "buf_len";
		}
	}
	else if (func == cmd_device_mock_get_reset_counter) {
		switch (arg) {
			case 0:
				return "type";

			case 1:
				return "port";

			case 2:
				return "counter";
		}
	}
	else if (func == cmd_device_mock_get_heap_stats) {
		switch (arg) {
			case 0:
				return "heap";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the device command handler API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int cmd_device_mock_init (struct cmd_device_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cmd_device_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cmd_device");

	mock->base.get_uuid = cmd_device_mock_get_uuid;
	mock->base.reset = cmd_device_mock_reset;
	mock->base.get_reset_counter = cmd_device_mock_get_reset_counter;
	mock->base.get_heap_stats = cmd_device_mock_get_heap_stats;

	mock->mock.func_arg_count = cmd_device_mock_func_arg_count;
	mock->mock.func_name_map = cmd_device_mock_func_name_map;
	mock->mock.arg_name_map = cmd_device_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock device command handler API instance.
 *
 * @param mock The mock to release.
 */
void cmd_device_mock_release (struct cmd_device_mock *mock)
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
int cmd_device_mock_validate_and_release (struct cmd_device_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cmd_device_mock_release (mock);
	}

	return status;
}
