// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "firmware_update_control_mock.h"


int firmware_update_control_mock_start_update (struct firmware_update_control *update)
{
	struct firmware_update_control_mock *mock = (struct firmware_update_control_mock*) update;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, firmware_update_control_mock_start_update, update);
}

int firmware_update_control_mock_get_status (struct firmware_update_control *update)
{
	struct firmware_update_control_mock *mock = (struct firmware_update_control_mock*) update;

	if (mock == NULL) {
		return UPDATE_STATUS_UNKNOWN;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, firmware_update_control_mock_get_status, update);
}

int32_t firmware_update_control_mock_get_remaining_len (struct firmware_update_control *update)
{
	struct firmware_update_control_mock *mock = (struct firmware_update_control_mock*) update;

	if (mock == NULL) {
		return UPDATE_STATUS_UNKNOWN;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, firmware_update_control_mock_get_remaining_len, update);
}

int firmware_update_control_mock_prepare_staging (struct firmware_update_control *update,
	size_t size)
{
	struct firmware_update_control_mock *mock = (struct firmware_update_control_mock*) update;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_update_control_mock_prepare_staging, update,
		MOCK_ARG_CALL (size));
}

int firmware_update_control_mock_write_staging (struct firmware_update_control *update,
	uint8_t *buf, size_t buf_len)
{
	struct firmware_update_control_mock *mock = (struct firmware_update_control_mock*) update;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, firmware_update_control_mock_write_staging, update,
		MOCK_ARG_CALL (buf), MOCK_ARG_CALL (buf_len));
}

static int firmware_update_control_mock_func_arg_count (void *func)
{
	if (func == firmware_update_control_mock_prepare_staging) {
		return 1;
	}
	else if (func == firmware_update_control_mock_write_staging) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* firmware_update_control_mock_func_name_map (void *func)
{
	if (func == firmware_update_control_mock_start_update) {
		return "start_update";
	}
	else if (func == firmware_update_control_mock_get_status) {
		return "get_status";
	}
	else if (func == firmware_update_control_mock_get_remaining_len) {
		return "get_remaining_len";
	}
	else if (func == firmware_update_control_mock_prepare_staging) {
		return "prepare_staging";
	}
	else if (func == firmware_update_control_mock_write_staging) {
		return "write_staging";
	}
	else {
		return "unknown";
	}
}

static const char* firmware_update_control_mock_arg_name_map (void *func, int arg)
{
	if (func == firmware_update_control_mock_prepare_staging) {
		switch (arg) {
			case 0:
				return "size";

			default:
				return "unknown";
		}
	}
	else if (func == firmware_update_control_mock_write_staging) {
		switch (arg) {
			case 0:
				return "buf";

			case 1:
				return "buf_len";

			default:
				return "unknown";
		}
	}
	else {
		return "unknown";
	}
}

/**
 * Initialize a mock instance for a firmware update control API.
 *
 * @param mock The mock instance to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int firmware_update_control_mock_init (struct firmware_update_control_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct firmware_update_control_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "firmware_update_control");

	mock->base.start_update = firmware_update_control_mock_start_update;
	mock->base.get_status = firmware_update_control_mock_get_status;
	mock->base.get_remaining_len = firmware_update_control_mock_get_remaining_len;
	mock->base.prepare_staging = firmware_update_control_mock_prepare_staging;
	mock->base.write_staging = firmware_update_control_mock_write_staging;

	mock->mock.func_arg_count = firmware_update_control_mock_func_arg_count;
	mock->mock.func_name_map = firmware_update_control_mock_func_name_map;
	mock->mock.arg_name_map = firmware_update_control_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock firmware update control API.
 *
 * @param mock The mock instance to release.
 */
void firmware_update_control_mock_release (struct firmware_update_control_mock *mock)
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
int firmware_update_control_mock_validate_and_release (struct firmware_update_control_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		firmware_update_control_mock_release (mock);
	}

	return status;
}
