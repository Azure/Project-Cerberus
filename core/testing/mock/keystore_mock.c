// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "keystore_mock.h"


static int keystore_mock_save_key (struct keystore *store, int id, const uint8_t *key,
	size_t length)
{
	struct keystore_mock *mock = (struct keystore_mock*) store;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, keystore_mock_save_key, store, MOCK_ARG_CALL (id),
		MOCK_ARG_CALL (key), MOCK_ARG_CALL (length));
}

static int keystore_mock_load_key (struct keystore *store, int id, uint8_t **key, size_t *length)
{
	struct keystore_mock *mock = (struct keystore_mock*) store;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, keystore_mock_load_key, store, MOCK_ARG_CALL (id),
		MOCK_ARG_CALL (key), MOCK_ARG_CALL (length));
}

static int keystore_mock_erase_key (struct keystore *store, int id)
{
	struct keystore_mock *mock = (struct keystore_mock*) store;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, keystore_mock_erase_key, store, MOCK_ARG_CALL (id));
}

static int keystore_mock_erase_all_keys (struct keystore *store)
{
	struct keystore_mock *mock = (struct keystore_mock*) store;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, keystore_mock_erase_all_keys, store);
}

static int keystore_mock_func_arg_count (void *func)
{
	if ((func == keystore_mock_save_key) || (func == keystore_mock_load_key)) {
		return 3;
	}
	else if (func == keystore_mock_erase_key) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* keystore_mock_func_name_map (void *func)
{
	if (func == keystore_mock_save_key) {
		return "save_key";
	}
	else if (func == keystore_mock_load_key) {
		return "load_key";
	}
	else if (func == keystore_mock_erase_key) {
		return "erase_key";
	}
	else if (func == keystore_mock_erase_all_keys) {
		return "erase_all_keys";
	}
	else {
		return "unknown";
	}
}

static const char* keystore_mock_arg_name_map (void *func, int arg)
{
	if ((func == keystore_mock_save_key) || (func == keystore_mock_load_key)) {
		switch (arg) {
			case 0:
				return "id";

			case 1:
				return "key";

			case 2:
				return "length";
		}
	}
	else if (func == keystore_mock_erase_key) {
		switch (arg) {
			case 0:
				return "id";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock interface for key storage.
 *
 * @param mock The keystore mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int keystore_mock_init (struct keystore_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct keystore_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "keystore");

	mock->base.save_key = keystore_mock_save_key;
	mock->base.load_key = keystore_mock_load_key;
	mock->base.erase_key = keystore_mock_erase_key;
	mock->base.erase_all_keys = keystore_mock_erase_all_keys;

	mock->mock.func_arg_count = keystore_mock_func_arg_count;
	mock->mock.func_name_map = keystore_mock_func_name_map;
	mock->mock.arg_name_map = keystore_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a keystore mock.
 *
 * @param mock The mock to release.
 */
void keystore_mock_release (struct keystore_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int keystore_mock_validate_and_release (struct keystore_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		keystore_mock_release (mock);
	}

	return status;
}
