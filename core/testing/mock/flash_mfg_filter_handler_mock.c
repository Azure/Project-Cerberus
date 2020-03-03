// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "flash_mfg_filter_handler_mock.h"


static int flash_mfg_filter_handler_mock_set_flash_manufacturer (
	struct flash_mfg_filter_handler *handler, uint8_t vendor, uint16_t device)
{
	struct flash_mfg_filter_handler_mock *mock = (struct flash_mfg_filter_handler_mock*) handler;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_mfg_filter_handler_mock_set_flash_manufacturer, handler,
		MOCK_ARG_CALL (vendor), MOCK_ARG_CALL (device));
}

static int flash_mfg_filter_handler_mock_func_arg_count (void *func)
{
	if (func == flash_mfg_filter_handler_mock_set_flash_manufacturer) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* flash_mfg_filter_handler_mock_func_name_map (void *func)
{
	if (func == flash_mfg_filter_handler_mock_set_flash_manufacturer) {
		return "set_flash_manufacturer";
	}
	else {
		return "unknown";
	}
}

static const char* flash_mfg_filter_handler_mock_arg_name_map (void *func, int arg)
{
	if (func == flash_mfg_filter_handler_mock_set_flash_manufacturer) {
		switch (arg) {
			case 0:
				return "vendor";

			case 1:
				return "device";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for the flash manufacturer handler API.
 *
 * @param mock The mock instance to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int flash_mfg_filter_handler_mock_init (struct flash_mfg_filter_handler_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct flash_mfg_filter_handler_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "flash_mfg_filter_handler");

	mock->base.set_flash_manufacturer = flash_mfg_filter_handler_mock_set_flash_manufacturer;

	mock->mock.func_arg_count = flash_mfg_filter_handler_mock_func_arg_count;
	mock->mock.func_name_map = flash_mfg_filter_handler_mock_func_name_map;
	mock->mock.arg_name_map = flash_mfg_filter_handler_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock flash manufacturer API.
 *
 * @param mock The mock to release.
 */
void flash_mfg_filter_handler_mock_release (struct flash_mfg_filter_handler_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that a flash manufacturer API mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int flash_mfg_filter_handler_mock_validate_and_release (struct flash_mfg_filter_handler_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		flash_mfg_filter_handler_mock_release (mock);
	}

	return status;
}
