// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "flash_store_mock.h"


static int flash_store_mock_write (struct flash_store *flash, int id, const uint8_t *data,
	size_t length)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_store_mock_write, flash, MOCK_ARG_CALL (id),
		MOCK_ARG_CALL (data), MOCK_ARG_CALL (length));
}

static int flash_store_mock_read (struct flash_store *flash, int id, uint8_t *data, size_t length)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_store_mock_read, flash, MOCK_ARG_CALL (id),
		MOCK_ARG_CALL (data), MOCK_ARG_CALL (length));
}

static int flash_store_mock_erase (struct flash_store *flash, int id)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_store_mock_erase, flash, MOCK_ARG_CALL (id));
}

static int flash_store_mock_erase_all (struct flash_store *flash)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, flash_store_mock_erase_all, flash);
}

static int flash_store_mock_get_data_length (struct flash_store *flash, int id)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_store_mock_get_data_length, flash, MOCK_ARG_CALL (id));
}

static int flash_store_mock_has_data_stored (struct flash_store *flash, int id)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, flash_store_mock_has_data_stored, flash, MOCK_ARG_CALL (id));
}

static int flash_store_mock_get_max_data_length (struct flash_store *flash)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, flash_store_mock_get_max_data_length, flash);
}

static int flash_store_mock_get_flash_size (struct flash_store *flash)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, flash_store_mock_get_flash_size, flash);
}

static int flash_store_mock_get_num_blocks (struct flash_store *flash)
{
	struct flash_store_mock *mock = (struct flash_store_mock*) flash;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, flash_store_mock_get_num_blocks, flash);
}

static int flash_store_mock_func_arg_count (void *func)
{
	if ((func == flash_store_mock_write) || (func == flash_store_mock_read)) {
		return 3;
	}
	else if ((func == flash_store_mock_erase) || (func == flash_store_mock_get_data_length) ||
		(func == flash_store_mock_has_data_stored)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* flash_store_mock_func_name_map (void *func)
{
	if (func == flash_store_mock_write) {
		return "write";
	}
	else if (func == flash_store_mock_read) {
		return "read";
	}
	else if (func == flash_store_mock_erase) {
		return "erase";
	}
	else if (func == flash_store_mock_erase_all) {
		return "erase_all";
	}
	else if (func == flash_store_mock_get_data_length) {
		return "get_data_length";
	}
	else if (func == flash_store_mock_has_data_stored) {
		return "has_data_stored";
	}
	else if (func == flash_store_mock_get_max_data_length) {
		return "get_max_data_length";
	}
	else if (func == flash_store_mock_get_flash_size) {
		return "get_flash_size";
	}
	else if (func == flash_store_mock_get_num_blocks) {
		return "get_num_blocks";
	}
	else {
		return "unknown";
	}
}

static const char* flash_store_mock_arg_name_map (void *func, int arg)
{
	if (func == flash_store_mock_write) {
		switch (arg) {
			case 0:
				return "id";

			case 1:
				return "data";

			case 2:
				return "length";
		}
	}
	else if (func == flash_store_mock_read) {
		switch (arg) {
			case 0:
				return "id";

			case 1:
				return "data";

			case 2:
				return "length";
		}
	}
	else if (func == flash_store_mock_erase) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == flash_store_mock_get_data_length) {
		switch (arg) {
			case 0:
				return "id";
		}
	}
	else if (func == flash_store_mock_has_data_stored) {
		switch (arg) {
			case 0:
				return "id";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for the flash block storage API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int flash_store_mock_init (struct flash_store_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct flash_store_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "flash_store");

	mock->base.write = flash_store_mock_write;
	mock->base.read = flash_store_mock_read;
	mock->base.erase = flash_store_mock_erase;
	mock->base.erase_all = flash_store_mock_erase_all;
	mock->base.get_data_length = flash_store_mock_get_data_length;
	mock->base.has_data_stored = flash_store_mock_has_data_stored;
	mock->base.get_max_data_length = flash_store_mock_get_max_data_length;
	mock->base.get_flash_size = flash_store_mock_get_flash_size;
	mock->base.get_num_blocks = flash_store_mock_get_num_blocks;

	mock->mock.func_arg_count = flash_store_mock_func_arg_count;
	mock->mock.func_name_map = flash_store_mock_func_name_map;
	mock->mock.arg_name_map = flash_store_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by the mock API.
 *
 * @param mock The mock to release.
 */
void flash_store_mock_release (struct flash_store_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate all mock expectations were called and released the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int flash_store_mock_validate_and_release (struct flash_store_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		flash_store_mock_release (mock);
	}

	return status;
}
