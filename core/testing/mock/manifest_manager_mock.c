// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "manifest_manager_mock.h"


static int manifest_manager_mock_activate_pending_manifest (struct manifest_manager *manager)
{
	struct manifest_manager_mock *mock = (struct manifest_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, manifest_manager_mock_activate_pending_manifest, manager);
}

static int manifest_manager_mock_clear_pending_region (struct manifest_manager *manager, size_t size)
{
	struct manifest_manager_mock *mock = (struct manifest_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_manager_mock_clear_pending_region, manager,
		MOCK_ARG_CALL (size));
}

static int manifest_manager_mock_write_pending_data (struct manifest_manager *manager,
	const uint8_t *data, size_t length)
{
	struct manifest_manager_mock *mock = (struct manifest_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, manifest_manager_mock_write_pending_data, manager, MOCK_ARG_CALL (data),
		MOCK_ARG_CALL (length));
}

static int manifest_manager_mock_verify_pending_manifest (struct manifest_manager *manager)
{
	struct manifest_manager_mock *mock = (struct manifest_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, manifest_manager_mock_verify_pending_manifest, manager);
}

static int manifest_manager_mock_clear_all_manifests (struct manifest_manager *manager)
{
	struct manifest_manager_mock *mock = (struct manifest_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, manifest_manager_mock_clear_all_manifests, manager);
}

static int manifest_manager_mock_func_arg_count (void *func)
{
	if (func == manifest_manager_mock_write_pending_data) {
		return 2;
	}
	else if (func == manifest_manager_mock_clear_pending_region) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* manifest_manager_mock_func_name_map (void *func)
{
	if (func == manifest_manager_mock_activate_pending_manifest) {
		return "activate_pending_pfm";
	}
	else if (func == manifest_manager_mock_clear_pending_region) {
		return "clear_pending_region";
	}
	else if (func == manifest_manager_mock_write_pending_data) {
		return "write_pending_data";
	}
	else if (func == manifest_manager_mock_verify_pending_manifest) {
		return "verify_pending_pfm";
	}
	else if (func == manifest_manager_mock_clear_all_manifests) {
		return "clear_all_manifests";
	}
	else {
		return "unknown";
	}
}

static const char* manifest_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == manifest_manager_mock_clear_pending_region) {
		switch (arg) {
			case 0:
				return "size";
		}
	}
	else if (func == manifest_manager_mock_write_pending_data) {
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
 * Initialize the mock instance for manifest management.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int manifest_manager_mock_init (struct manifest_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct manifest_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "manifest_manager");

	mock->base.activate_pending_manifest = manifest_manager_mock_activate_pending_manifest;
	mock->base.clear_pending_region = manifest_manager_mock_clear_pending_region;
	mock->base.write_pending_data = manifest_manager_mock_write_pending_data;
	mock->base.verify_pending_manifest = manifest_manager_mock_verify_pending_manifest;
	mock->base.clear_all_manifests = manifest_manager_mock_clear_all_manifests;

	mock->mock.func_arg_count = manifest_manager_mock_func_arg_count;
	mock->mock.func_name_map = manifest_manager_mock_func_name_map;
	mock->mock.arg_name_map = manifest_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a manifest management mock.
 *
 * @param mock The mock to release.
 */
void manifest_manager_mock_release (struct manifest_manager_mock *mock)
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
int manifest_manager_mock_validate_and_release (struct manifest_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		manifest_manager_mock_release (mock);
	}

	return status;
}
