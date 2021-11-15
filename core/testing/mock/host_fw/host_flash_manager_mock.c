// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "host_flash_manager_mock.h"


static struct spi_flash* host_flash_manager_mock_get_read_only_flash (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct spi_flash*,
		host_flash_manager_mock_get_read_only_flash, manager);
}

static struct spi_flash* host_flash_manager_mock_get_read_write_flash (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return NULL;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, struct spi_flash*,
		host_flash_manager_mock_get_read_write_flash, manager);
}

static int host_flash_manager_mock_validate_read_only_flash (struct host_flash_manager *manager,
	struct pfm *pfm, struct pfm *good_pfm, struct hash_engine *hash, struct rsa_engine *rsa,
	bool full_validation, struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_validate_read_only_flash, manager,
		MOCK_ARG_CALL (pfm), MOCK_ARG_CALL (good_pfm), MOCK_ARG_CALL (hash), MOCK_ARG_CALL (rsa),
		MOCK_ARG_CALL (full_validation), MOCK_ARG_CALL (host_rw));
}

static int host_flash_manager_mock_validate_read_write_flash (struct host_flash_manager *manager,
	struct pfm *pfm, struct hash_engine *hash, struct rsa_engine *rsa,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_validate_read_write_flash, manager,
		MOCK_ARG_CALL (pfm), MOCK_ARG_CALL (hash), MOCK_ARG_CALL (rsa), MOCK_ARG_CALL (host_rw));
}

static int host_flash_manager_mock_get_flash_read_write_regions (struct host_flash_manager *manager,
	struct pfm *pfm, bool rw_flash, struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_get_flash_read_write_regions, manager,
		MOCK_ARG_CALL (pfm), MOCK_ARG_CALL (rw_flash), MOCK_ARG_CALL (host_rw));
}

static void host_flash_manager_mock_free_read_write_regions (struct host_flash_manager *manager,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return;
	}

	MOCK_VOID_RETURN (&mock->mock, host_flash_manager_mock_free_read_write_regions, manager,
		MOCK_ARG_CALL (host_rw));
}

static int host_flash_manager_mock_config_spi_filter_flash_type (struct host_flash_manager *manager)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_flash_manager_mock_config_spi_filter_flash_type,
		manager);
}

static int host_flash_manager_mock_config_spi_filter_flash_devices (
	struct host_flash_manager *manager)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, host_flash_manager_mock_config_spi_filter_flash_devices,
		manager);
}

static int host_flash_manager_mock_swap_flash_devices (struct host_flash_manager *manager,
	struct host_flash_manager_rw_regions *host_rw, struct pfm_manager *used_pending)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_swap_flash_devices, manager,
		MOCK_ARG_CALL (host_rw), MOCK_ARG_CALL (used_pending));
}

static int host_flash_manager_mock_initialize_flash_protection (struct host_flash_manager *manager,
	struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_initialize_flash_protection, manager,
		MOCK_ARG_CALL (host_rw));
}

static int host_flash_manager_mock_restore_flash_read_write_regions (
	struct host_flash_manager *manager, struct host_flash_manager_rw_regions *host_rw)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_restore_flash_read_write_regions, manager,
		MOCK_ARG_CALL (host_rw));
}

static int host_flash_manager_mock_set_flash_for_rot_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_set_flash_for_rot_access, manager,
		MOCK_ARG_CALL (control));
}

static int host_flash_manager_mock_set_flash_for_host_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_set_flash_for_host_access, manager,
		MOCK_ARG_CALL (control));
}

static int host_flash_manager_mock_host_has_flash_access (struct host_flash_manager *manager,
	struct host_control *control)
{
	struct host_flash_manager_mock *mock = (struct host_flash_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, host_flash_manager_mock_host_has_flash_access, manager,
		MOCK_ARG_CALL (control));
}

static int host_flash_manager_mock_func_arg_count (void *func)
{
	if (func == host_flash_manager_mock_validate_read_only_flash) {
		return 6;
	}
	else if (func == host_flash_manager_mock_validate_read_write_flash) {
		return 4;
	}
	else if (func == host_flash_manager_mock_get_flash_read_write_regions) {
		return 3;
	}
	else if (func == host_flash_manager_mock_swap_flash_devices) {
		return 2;
	}
	else if ((func == host_flash_manager_mock_initialize_flash_protection) ||
		(func == host_flash_manager_mock_set_flash_for_rot_access) ||
		(func == host_flash_manager_mock_set_flash_for_host_access) ||
		(func == host_flash_manager_mock_host_has_flash_access) ||
		(func == host_flash_manager_mock_restore_flash_read_write_regions) ||
		(func == host_flash_manager_mock_free_read_write_regions)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* host_flash_manager_mock_func_name_map (void *func)
{
	if (func == host_flash_manager_mock_get_read_only_flash) {
		return "get_read_only_flash";
	}
	else if (func == host_flash_manager_mock_get_read_write_flash) {
		return "get_read_write_flash";
	}
	else if (func == host_flash_manager_mock_validate_read_only_flash) {
		return "validate_read_only_flash";
	}
	else if (func == host_flash_manager_mock_validate_read_write_flash) {
		return "validate_read_write_flash";
	}
	else if (func == host_flash_manager_mock_get_flash_read_write_regions) {
		return "get_flash_read_write_regions";
	}
	else if (func == host_flash_manager_mock_free_read_write_regions) {
		return "free_read_write_regions";
	}
	else if (func == host_flash_manager_mock_config_spi_filter_flash_type) {
		return "config_spi_filter_flash_type";
	}
	else if (func == host_flash_manager_mock_config_spi_filter_flash_devices) {
		return "config_spi_filter_flash_devices";
	}
	else if (func == host_flash_manager_mock_swap_flash_devices) {
		return "swap_flash_devices";
	}
	else if (func == host_flash_manager_mock_initialize_flash_protection) {
		return "initialize_flash_protection";
	}
	else if (func == host_flash_manager_mock_restore_flash_read_write_regions) {
		return "restore_flash_read_write_regions";
	}
	else if (func == host_flash_manager_mock_set_flash_for_rot_access) {
		return "set_flash_for_rot_access";
	}
	else if (func == host_flash_manager_mock_set_flash_for_host_access) {
		return "set_flash_for_host_access";
	}
	else if (func == host_flash_manager_mock_host_has_flash_access) {
		return "host_has_flash_access";
	}
	else {
		return "unknown";
	}
}

static const char* host_flash_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == host_flash_manager_mock_validate_read_only_flash) {
		switch (arg) {
			case 0:
				return "pfm";

			case 1:
				return "good_pfm";

			case 2:
				return "hash";

			case 3:
				return "rsa";

			case 4:
				return "full_validation";

			case 5:
				return "host_rw";
		}
	}
	else if (func == host_flash_manager_mock_validate_read_write_flash) {
		switch (arg) {
			case 0:
				return "pfm";

			case 1:
				return "hash";

			case 2:
				return "rsa";

			case 3:
				return "host_rw";
		}
	}
	else if (func == host_flash_manager_mock_get_flash_read_write_regions) {
		switch (arg) {
			case 0:
				return "pfm";

			case 1:
				return "rw_flash";

			case 2:
				return "host_rw";
		}
	}
	else if (func == host_flash_manager_mock_free_read_write_regions) {
		switch (arg) {
			case 0:
				return "host_rw";
		}
	}
	else if (func == host_flash_manager_mock_swap_flash_devices) {
		switch (arg) {
			case 0:
				return "host_rw";

			case 1:
				return "used_pending";
		}
	}
	else if (func == host_flash_manager_mock_initialize_flash_protection) {
		switch (arg) {
			case 0:
				return "host_rw";
		}
	}
	else if (func == host_flash_manager_mock_restore_flash_read_write_regions) {
		switch (arg) {
			case 0:
				return "host_rw";
		}
	}
	else if (func == host_flash_manager_mock_set_flash_for_rot_access) {
		switch (arg) {
			case 0:
				return "control";
		}
	}
	else if (func == host_flash_manager_mock_set_flash_for_host_access) {
		switch (arg) {
			case 0:
				return "control";
		}
	}
	else if (func == host_flash_manager_mock_host_has_flash_access) {
		switch (arg) {
			case 0:
				return "control";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a manager of protected flash.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int host_flash_manager_mock_init (struct host_flash_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct host_flash_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "host_flash_manager");

	mock->base.get_read_only_flash = host_flash_manager_mock_get_read_only_flash;
	mock->base.get_read_write_flash = host_flash_manager_mock_get_read_write_flash;
	mock->base.validate_read_only_flash = host_flash_manager_mock_validate_read_only_flash;
	mock->base.validate_read_write_flash = host_flash_manager_mock_validate_read_write_flash;
	mock->base.get_flash_read_write_regions = host_flash_manager_mock_get_flash_read_write_regions;
	mock->base.free_read_write_regions = host_flash_manager_mock_free_read_write_regions;
	mock->base.config_spi_filter_flash_type = host_flash_manager_mock_config_spi_filter_flash_type;
	mock->base.config_spi_filter_flash_devices =
		host_flash_manager_mock_config_spi_filter_flash_devices;
	mock->base.swap_flash_devices = host_flash_manager_mock_swap_flash_devices;
	mock->base.initialize_flash_protection = host_flash_manager_mock_initialize_flash_protection;
	mock->base.restore_flash_read_write_regions =
		host_flash_manager_mock_restore_flash_read_write_regions;
	mock->base.set_flash_for_rot_access = host_flash_manager_mock_set_flash_for_rot_access;
	mock->base.set_flash_for_host_access = host_flash_manager_mock_set_flash_for_host_access;
	mock->base.host_has_flash_access = host_flash_manager_mock_host_has_flash_access;

	mock->mock.func_arg_count = host_flash_manager_mock_func_arg_count;
	mock->mock.func_name_map = host_flash_manager_mock_func_name_map;
	mock->mock.arg_name_map = host_flash_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by flash manager mock instance.
 *
 * @param mock The mock to release.
 */
void host_flash_manager_mock_release (struct host_flash_manager_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that the flash manager mock was called as expected and release the instance.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int host_flash_manager_mock_validate_and_release (struct host_flash_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		host_flash_manager_mock_release (mock);
	}

	return status;
}
