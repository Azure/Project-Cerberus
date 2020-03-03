// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_cmd_interface_mock.h"


static int manifest_cmd_interface_mock_prepare_manifest (struct manifest_cmd_interface *cmd,
	uint32_t manifest_size)
{
	struct manifest_cmd_interface_mock *mock = (struct manifest_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_cmd_interface_mock_prepare_manifest, cmd,
		MOCK_ARG_CALL (manifest_size));
}

static int manifest_cmd_interface_mock_store_manifest (struct manifest_cmd_interface *cmd,
	const uint8_t *data, size_t length)
{
	struct manifest_cmd_interface_mock *mock = (struct manifest_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_cmd_interface_mock_store_manifest, cmd, MOCK_ARG_CALL (data),
		MOCK_ARG_CALL (length));
}

static int manifest_cmd_interface_mock_finish_manifest (struct manifest_cmd_interface *cmd,
	bool activate)
{
	struct manifest_cmd_interface_mock *mock = (struct manifest_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_cmd_interface_mock_finish_manifest, cmd,
		MOCK_ARG_CALL (activate));
}

static int manifest_cmd_interface_mock_get_status (struct manifest_cmd_interface *cmd)
{
	struct manifest_cmd_interface_mock *mock = (struct manifest_cmd_interface_mock*) cmd;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, manifest_cmd_interface_mock_get_status, cmd);
}

static int manifest_cmd_interface_mock_func_arg_count (void *func)
{
	if (func == manifest_cmd_interface_mock_store_manifest) {
		return 2;
	}
	else if ((func == manifest_cmd_interface_mock_prepare_manifest) ||
		(func == manifest_cmd_interface_mock_finish_manifest)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* manifest_cmd_interface_mock_func_name_map (void *func)
{
	if (func == manifest_cmd_interface_mock_prepare_manifest) {
		return "prepare_manifest";
	}
	else if (func == manifest_cmd_interface_mock_store_manifest) {
		return "store_manifest";
	}
	else if (func == manifest_cmd_interface_mock_finish_manifest) {
		return "finish_manifest";
	}
	else if (func == manifest_cmd_interface_mock_get_status) {
		return "get_status";
	}
	else {
		return "unknown";
	}
}

static const char* manifest_cmd_interface_mock_arg_name_map (void *func, int arg)
{
	if (func == manifest_cmd_interface_mock_prepare_manifest) {
		switch (arg) {
			case 0:
				return "manifest_size";
		}
	}
	else if (func == manifest_cmd_interface_mock_store_manifest) {
		switch (arg) {
			case 0:
				return "data";

			case 1:
				return "length";
		}
	}
	else if (func == manifest_cmd_interface_mock_finish_manifest) {
		switch (arg) {
			case 0:
				return "activate";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock command handler for manifest operations.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int manifest_cmd_interface_mock_init (struct manifest_cmd_interface_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct manifest_cmd_interface_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "manifest_cmd_interface");

	mock->base.prepare_manifest = manifest_cmd_interface_mock_prepare_manifest;
	mock->base.store_manifest = manifest_cmd_interface_mock_store_manifest;
	mock->base.finish_manifest = manifest_cmd_interface_mock_finish_manifest;
	mock->base.get_status = manifest_cmd_interface_mock_get_status;

	mock->mock.func_arg_count = manifest_cmd_interface_mock_func_arg_count;
	mock->mock.func_name_map = manifest_cmd_interface_mock_func_name_map;
	mock->mock.arg_name_map = manifest_cmd_interface_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock manifest command handler.
 *
 * @param mock The mock to release.
 */
void manifest_cmd_interface_mock_release (struct manifest_cmd_interface_mock *mock)
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
int manifest_cmd_interface_mock_validate_and_release (struct manifest_cmd_interface_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		manifest_cmd_interface_mock_release (mock);
	}

	return status;
}
