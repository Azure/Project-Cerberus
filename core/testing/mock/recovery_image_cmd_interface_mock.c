// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "recovery_image_cmd_interface_mock.h"


static int recovery_image_cmd_interface_mock_prepare_recovery_image (
	struct recovery_image_cmd_interface *cmd, uint32_t image_size)
{
	struct recovery_image_cmd_interface_mock *mock =
		(struct recovery_image_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, recovery_image_cmd_interface_mock_prepare_recovery_image, cmd,
		MOCK_ARG_CALL (image_size));
}

static int recovery_image_cmd_interface_mock_update_recovery_image (
	struct recovery_image_cmd_interface *cmd, const uint8_t *data, size_t length)
{
	struct recovery_image_cmd_interface_mock *mock = (
		struct recovery_image_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, recovery_image_cmd_interface_mock_update_recovery_image, cmd,
		MOCK_ARG_CALL (data), MOCK_ARG_CALL (length));
}

static int recovery_image_cmd_interface_mock_activate_recovery_image (
	struct recovery_image_cmd_interface *cmd)
{
	struct recovery_image_cmd_interface_mock *mock = (
		struct recovery_image_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, recovery_image_cmd_interface_mock_activate_recovery_image,
		cmd);
}

static int recovery_image_cmd_interface_mock_get_status (struct recovery_image_cmd_interface *cmd)
{
	struct recovery_image_cmd_interface_mock *mock = (
		struct recovery_image_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, recovery_image_cmd_interface_mock_get_status, cmd);
}

static int recovery_image_cmd_interface_mock_func_arg_count (void *func)
{
	if (func == recovery_image_cmd_interface_mock_update_recovery_image) {
		return 2;
	}
	else if (func == recovery_image_cmd_interface_mock_prepare_recovery_image) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* recovery_image_cmd_interface_mock_func_name_map (void *func)
{
	if (func == recovery_image_cmd_interface_mock_prepare_recovery_image) {
		return "prepare_recovery_image";
	}
	else if (func == recovery_image_cmd_interface_mock_update_recovery_image) {
		return "update_recovery_image";
	}
	else if (func == recovery_image_cmd_interface_mock_activate_recovery_image) {
		return "activate_recovery_image";
	}
	else if (func == recovery_image_cmd_interface_mock_get_status) {
		return "get_status";
	}
	else {
		return "unknown";
	}
}

static const char* recovery_image_cmd_interface_mock_arg_name_map (void *func, int arg)
{
	if (func == recovery_image_cmd_interface_mock_prepare_recovery_image) {
		switch (arg) {
			case 0:
				return "image_size";
		}
	}
	else if (func == recovery_image_cmd_interface_mock_update_recovery_image) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock command handler for recovery image operations.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int recovery_image_cmd_interface_mock_init (struct recovery_image_cmd_interface_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct recovery_image_cmd_interface_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "recovery_image_cmd_interface");

	mock->base.prepare_recovery_image = recovery_image_cmd_interface_mock_prepare_recovery_image;
	mock->base.update_recovery_image = recovery_image_cmd_interface_mock_update_recovery_image;
	mock->base.activate_recovery_image = recovery_image_cmd_interface_mock_activate_recovery_image;
	mock->base.get_status = recovery_image_cmd_interface_mock_get_status;

	mock->mock.func_arg_count = recovery_image_cmd_interface_mock_func_arg_count;
	mock->mock.func_name_map = recovery_image_cmd_interface_mock_func_name_map;
	mock->mock.arg_name_map = recovery_image_cmd_interface_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock recovery image command handler.
 *
 * @param mock The mock to release.
 */
void recovery_image_cmd_interface_mock_release (struct recovery_image_cmd_interface_mock *mock)
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
int recovery_image_cmd_interface_mock_validate_and_release (
	struct recovery_image_cmd_interface_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		recovery_image_cmd_interface_mock_release (mock);
	}

	return status;
}
