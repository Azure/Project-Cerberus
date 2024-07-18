// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "key_cache_mock.h"
#include "keystore/key_cache.h"


static bool key_cache_mock_is_full (const struct key_cache *store)
{
	struct key_cache_mock *mock = (struct key_cache_mock*) store;

	if (mock == NULL) {
		return false;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, bool, key_cache_mock_is_full, store);
}

static bool key_cache_mock_is_empty (const struct key_cache *store)
{
	struct key_cache_mock *mock = (struct key_cache_mock*) store;

	if (mock == NULL) {
		return false;
	}

	MOCK_RETURN_NO_ARGS_CAST (&mock->mock, bool, key_cache_mock_is_empty, store);
}

static int key_cache_mock_add_key (const struct key_cache *store, const uint8_t *key, size_t length)
{
	struct key_cache_mock *mock = (struct key_cache_mock*) store;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, key_cache_mock_add_key, store, MOCK_ARG_PTR_CALL (key),
		MOCK_ARG_CALL (length));
}

static int key_cache_mock_remove_key (const struct key_cache *store, uint32_t requestor_id,
	uint8_t *key, size_t key_buffer_size, size_t *length)
{
	struct key_cache_mock *mock = (struct key_cache_mock*) store;

	if (mock == NULL) {
		return false;
	}

	MOCK_RETURN (&mock->mock, key_cache_mock_remove_key, store, MOCK_ARG_CALL (requestor_id),
		MOCK_ARG_PTR_CALL (key), MOCK_ARG_CALL (key_buffer_size), MOCK_ARG_PTR_CALL (length));
}

static int key_cache_mock_func_arg_count (void *func)
{
	if (func == key_cache_mock_add_key) {
		return 2;
	}
	else if (func == key_cache_mock_remove_key) {
		return 4;
	}
	else {
		return 0;
	}
}

static const char* key_cache_mock_func_name_map (void *func)
{
	if (func == key_cache_mock_is_full) {
		return "is_full";
	}
	else if (func == key_cache_mock_is_empty) {
		return "is_empty";
	}
	else if (func == key_cache_mock_add_key) {
		return "add";
	}
	else if (func == key_cache_mock_remove_key) {
		return "remove";
	}
	else {
		return "unknown";
	}
}

static const char* key_cache_mock_arg_name_map (void *func, int arg)
{
	if (func == key_cache_mock_add_key) {
		switch (arg) {
			case 0:
				return "key";

			case 1:
				return "length";
		}
	}
	else if (func == key_cache_mock_remove_key) {
		switch (arg) {
			case 0:
				return "requestor_id";

			case 1:
				return "key";

			case 2:
				return "key_buffer_size";

			case 3:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock interface for a key cache.
 *
 * @param mock The key cache mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int key_cache_mock_init (struct key_cache_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct key_cache_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "key_cache");

	mock->base.is_full = key_cache_mock_is_full;
	mock->base.is_empty = key_cache_mock_is_empty;
	mock->base.add = key_cache_mock_add_key;
	mock->base.remove = key_cache_mock_remove_key;

	mock->mock.func_arg_count = key_cache_mock_func_arg_count;
	mock->mock.func_name_map = key_cache_mock_func_name_map;
	mock->mock.arg_name_map = key_cache_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a key cache mock.
 *
 * @param mock The mock to release.
 */
void key_cache_mock_release (struct key_cache_mock *mock)
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
int key_cache_mock_validate_and_release (struct key_cache_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		key_cache_mock_release (mock);
	}

	return status;
}
