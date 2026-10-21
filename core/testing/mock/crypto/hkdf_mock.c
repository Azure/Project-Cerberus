// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "hkdf_mock.h"


int hkdf_mock_extract (const struct hkdf_interface *hkdf, enum hash_type hash_algo,
	const uint8_t *ikm, size_t length, const uint8_t *salt, size_t salt_length)
{
	struct hkdf_mock *mock = (struct hkdf_mock*) hkdf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hkdf_mock_extract, hkdf, MOCK_ARG_CALL (hash_algo),
		MOCK_ARG_PTR_CALL (ikm), MOCK_ARG_CALL (length), MOCK_ARG_PTR_CALL (salt),
		MOCK_ARG_CALL (salt_length));
}

int hkdf_mock_expand (const struct hkdf_interface *hkdf, const uint8_t *info, size_t info_length,
	uint8_t *key_out, size_t key_length)
{
	struct hkdf_mock *mock = (struct hkdf_mock*) hkdf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hkdf_mock_expand, hkdf, MOCK_ARG_PTR_CALL (info),
		MOCK_ARG_CALL (info_length), MOCK_ARG_PTR_CALL (key_out), MOCK_ARG_CALL (key_length));
}

int hkdf_mock_update_prk (const struct hkdf_interface *hkdf, const uint8_t *info,
	size_t info_length)
{
	struct hkdf_mock *mock = (struct hkdf_mock*) hkdf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, hkdf_mock_update_prk, hkdf, MOCK_ARG_PTR_CALL (info),
		MOCK_ARG_CALL (info_length));
}

int hkdf_mock_clear_prk (const struct hkdf_interface *hkdf)
{
	struct hkdf_mock *mock = (struct hkdf_mock*) hkdf;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, hkdf_mock_clear_prk, hkdf);
}

static int hkdf_mock_func_arg_count (void *func)
{
	if (func == hkdf_mock_extract) {
		return 5;
	}
	else if (func == hkdf_mock_expand) {
		return 4;
	}
	else if (func == hkdf_mock_update_prk) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* hkdf_mock_func_name_map (void *func)
{
	if (func == hkdf_mock_extract) {
		return "extract";
	}
	else if (func == hkdf_mock_expand) {
		return "expand";
	}
	else if (func == hkdf_mock_update_prk) {
		return "update_prk";
	}
	else if (func == hkdf_mock_clear_prk) {
		return "clear_prk";
	}
	else {
		return "unknown";
	}
}

static const char* hkdf_mock_arg_name_map (void *func, int arg)
{
	if (func == hkdf_mock_extract) {
		switch (arg) {
			case 0:
				return "hash_algo";

			case 1:
				return "ikm";

			case 2:
				return "length";

			case 3:
				return "salt";

			case 4:
				return "salt_length";
		}
	}
	else if (func == hkdf_mock_expand) {
		switch (arg) {
			case 0:
				return "info";

			case 1:
				return "info_length";

			case 2:
				return "key_out";

			case 3:
				return "key_length";
		}
	}
	else if (func == hkdf_mock_update_prk) {
		switch (arg) {
			case 0:
				return "info";

			case 1:
				return "info_length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for the HKDF API.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int hkdf_mock_init (struct hkdf_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct hkdf_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "hkdf");

	mock->base.extract = hkdf_mock_extract;
	mock->base.expand = hkdf_mock_expand;
	mock->base.update_prk = hkdf_mock_update_prk;
	mock->base.clear_prk = hkdf_mock_clear_prk;

	mock->mock.func_arg_count = hkdf_mock_func_arg_count;
	mock->mock.func_name_map = hkdf_mock_func_name_map;
	mock->mock.arg_name_map = hkdf_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock HKDF API instance.
 *
 * @param mock The mock to release.
 */
void hkdf_mock_release (struct hkdf_mock *mock)
{
	if (mock) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify the mock was called as expected and release the instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int hkdf_mock_validate_and_release (struct hkdf_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		hkdf_mock_release (mock);
	}

	return status;
}
