// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "host_cmd_interface_mock.h"


static int host_cmd_interface_mock_get_next_host_verification (
	const struct host_cmd_interface *cmd, enum host_processor_reset_actions *action)
{
	struct host_cmd_interface_mock *mock = (struct host_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_cmd_interface_mock_get_next_host_verification, cmd,
		MOCK_ARG_PTR_CALL (action));
}

static int host_cmd_interface_mock_get_flash_configuration (const struct host_cmd_interface *cmd,
	spi_filter_flash_mode *mode, spi_filter_cs *current_ro, spi_filter_cs *next_ro,
	enum host_read_only_activation *apply_next_ro)
{
	struct host_cmd_interface_mock *mock = (struct host_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_cmd_interface_mock_get_flash_configuration, cmd,
		MOCK_ARG_PTR_CALL (mode), MOCK_ARG_PTR_CALL (current_ro), MOCK_ARG_PTR_CALL (next_ro),
		MOCK_ARG_PTR_CALL (apply_next_ro));
}

static int host_cmd_interface_mock_set_flash_configuration (const struct host_cmd_interface *cmd,
	int8_t current_ro, int8_t next_ro, int8_t apply_next_ro)
{
	struct host_cmd_interface_mock *mock = (struct host_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_cmd_interface_mock_set_flash_configuration, cmd,
		MOCK_ARG_CALL (current_ro), MOCK_ARG_CALL (next_ro), MOCK_ARG_CALL (apply_next_ro));
}

static int host_cmd_interface_mock_get_status (const struct host_cmd_interface *cmd)
{
	struct host_cmd_interface_mock *mock = (struct host_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_cmd_interface_mock_get_status, cmd);
}

static int host_cmd_interface_mock_func_arg_count (void *func)
{
	if (func == host_cmd_interface_mock_get_flash_configuration) {
		return 4;
	}
	else if (func == host_cmd_interface_mock_set_flash_configuration) {
		return 3;
	}
	else if (func == host_cmd_interface_mock_get_next_host_verification) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* host_cmd_interface_mock_func_name_map (void *func)
{
	if (func == host_cmd_interface_mock_get_next_host_verification) {
		return "get_next_host_verification";
	}
	else if (func == host_cmd_interface_mock_get_flash_configuration) {
		return "get_flash_configuration";
	}
	else if (func == host_cmd_interface_mock_set_flash_configuration) {
		return "set_flash_configuration";
	}
	else if (func == host_cmd_interface_mock_get_status) {
		return "get_status";
	}
	else {
		return "unknown";
	}
}

static const char* host_cmd_interface_mock_arg_name_map (void *func, int arg)
{
	if (func == host_cmd_interface_mock_get_next_host_verification) {
		switch (arg) {
			case 0:
				return "action";
		}
	}
	else if (func == host_cmd_interface_mock_get_flash_configuration) {
		switch (arg) {
			case 0:
				return "mode";

			case 1:
				return "current_ro";

			case 2:
				return "next_ro";

			case 3:
				return "apply_next_ro";
		}
	}
	else if (func == host_cmd_interface_mock_set_flash_configuration) {
		switch (arg) {
			case 0:
				return "current_ro";

			case 1:
				return "next_ro";

			case 2:
				return "apply_next_ro";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock command handler for host operations.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int host_cmd_interface_mock_init (struct host_cmd_interface_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct host_cmd_interface_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "host_cmd_interface");

	mock->base.get_next_host_verification = host_cmd_interface_mock_get_next_host_verification;
	mock->base.get_flash_configuration = host_cmd_interface_mock_get_flash_configuration;
	mock->base.set_flash_configuration = host_cmd_interface_mock_set_flash_configuration;
	mock->base.get_status = host_cmd_interface_mock_get_status;

	mock->mock.func_arg_count = host_cmd_interface_mock_func_arg_count;
	mock->mock.func_name_map = host_cmd_interface_mock_func_name_map;
	mock->mock.arg_name_map = host_cmd_interface_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock host command handler.
 *
 * @param mock The mock to release.
 */
void host_cmd_interface_mock_release (struct host_cmd_interface_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int host_cmd_interface_mock_validate_and_release (struct host_cmd_interface_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		host_cmd_interface_mock_release (mock);
	}

	return status;
}
