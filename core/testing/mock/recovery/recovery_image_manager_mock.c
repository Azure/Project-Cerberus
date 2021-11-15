// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <string.h>
#include "recovery_image_manager_mock.h"


static struct recovery_image* recovery_image_manager_mock_get_active_recovery_image (
	struct recovery_image_manager *manager)
{
	struct recovery_image_manager_mock *mock = (struct recovery_image_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct recovery_image*,
		recovery_image_manager_mock_get_active_recovery_image, manager);
}

static int recovery_image_manager_mock_clear_recovery_image_region (
	struct recovery_image_manager *manager, size_t max_size)
{
	struct recovery_image_manager_mock *mock = (struct recovery_image_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, recovery_image_manager_mock_clear_recovery_image_region, manager,
		MOCK_ARG_CALL (max_size));
}

static void recovery_image_manager_mock_free_recovery_image (
	struct recovery_image_manager *manager, struct recovery_image *image)
{
	struct recovery_image_manager_mock *mock = (struct recovery_image_manager_mock*) manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, recovery_image_manager_mock_free_recovery_image, manager,
		MOCK_ARG_CALL (image));
}

static int recovery_image_manager_mock_activate_recovery_image (
	struct recovery_image_manager *manager)
{
	struct recovery_image_manager_mock *mock = (struct recovery_image_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, recovery_image_manager_mock_activate_recovery_image, manager);
}

static int recovery_image_manager_mock_write_recovery_image_data (
	struct recovery_image_manager *manager, const uint8_t *data, size_t length)
{
	struct recovery_image_manager_mock *mock = (struct recovery_image_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, recovery_image_manager_mock_write_recovery_image_data, manager,
		MOCK_ARG_CALL (data), MOCK_ARG_CALL (length));
}

static struct flash_updater* recovery_image_manager_mock_get_flash_update_manager (
	struct recovery_image_manager *manager)
{
	struct recovery_image_manager_mock *mock = (struct recovery_image_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct flash_updater*,
		recovery_image_manager_mock_get_flash_update_manager, manager);
}

static int recovery_image_manager_mock_erase_all_recovery_regions (
	struct recovery_image_manager *manager)
{
	struct recovery_image_manager_mock *mock = (struct recovery_image_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, recovery_image_manager_mock_erase_all_recovery_regions,
		manager);
}

static int recovery_image_manager_mock_func_arg_count (void *func)
{
	if ((func == recovery_image_manager_mock_clear_recovery_image_region) ||
		(func == recovery_image_manager_mock_free_recovery_image)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* recovery_image_manager_mock_func_name_map (void *func)
{
	if (func == recovery_image_manager_mock_get_active_recovery_image) {
		return "get_active_recovery_image";
	}
	else if (func == recovery_image_manager_mock_clear_recovery_image_region) {
		return "clear_recovery_image_region";
	}
	else if (func == recovery_image_manager_mock_free_recovery_image) {
		return "free_recovery_image";
	}
	else if (func == recovery_image_manager_mock_activate_recovery_image) {
		return "activate_recovery_image";
	}
	else if (func == recovery_image_manager_mock_write_recovery_image_data) {
		return "write_recovery_image_data";
	}
	else if (func == recovery_image_manager_mock_get_flash_update_manager) {
		return "get_flash_update_manager";
	}
	else if (func == recovery_image_manager_mock_erase_all_recovery_regions) {
		return "erase_all_recovery_regions";
	}
	else {
		return "unknown";
	}
}

static const char* recovery_image_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == recovery_image_manager_mock_clear_recovery_image_region) {
		switch (arg) {
			case 0:
				return "size";
		}
	}
	else if (func == recovery_image_manager_mock_free_recovery_image) {
		switch (arg) {
			case 0:
				return "image";
		}
	}
	else if (func == recovery_image_manager_mock_write_recovery_image_data) {
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
 * Initialize the mock instance for recovery image management.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int recovery_image_manager_mock_init (struct recovery_image_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct recovery_image_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		recovery_image_manager_release (&mock->base);
		return status;
	}

	mock_set_name (&mock->mock, "recovery_image_manager");

	mock->base.get_active_recovery_image = recovery_image_manager_mock_get_active_recovery_image;
	mock->base.clear_recovery_image_region = recovery_image_manager_mock_clear_recovery_image_region;
	mock->base.free_recovery_image = recovery_image_manager_mock_free_recovery_image;
	mock->base.activate_recovery_image = recovery_image_manager_mock_activate_recovery_image;
	mock->base.write_recovery_image_data = recovery_image_manager_mock_write_recovery_image_data;
	mock->base.get_flash_update_manager = recovery_image_manager_mock_get_flash_update_manager;
	mock->base.erase_all_recovery_regions = recovery_image_manager_mock_erase_all_recovery_regions;

	mock->mock.func_arg_count = recovery_image_manager_mock_func_arg_count;
	mock->mock.func_name_map = recovery_image_manager_mock_func_name_map;
	mock->mock.arg_name_map = recovery_image_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a recovery image management mock.
 *
 * @param mock The mock to release.
 */
void recovery_image_manager_mock_release (struct recovery_image_manager_mock *mock)
{
	if (mock) {
		recovery_image_manager_release (&mock->base);
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
int recovery_image_manager_mock_validate_and_release (struct recovery_image_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		recovery_image_manager_mock_release (mock);
	}

	return status;
}
