// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <string.h>
#include "cert_device_hw_mock.h"


static int cert_device_hw_mock_verify_root_key (struct cert_device_hw *hw, const uint8_t *root_key,
	size_t key_length, struct hash_engine *hash)
{
	struct cert_device_hw_mock *mock = (struct cert_device_hw_mock*) hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cert_device_hw_mock_verify_root_key, hw, MOCK_ARG_CALL (root_key),
		MOCK_ARG_CALL (key_length), MOCK_ARG_CALL (hash));
}

static int cert_device_hw_mock_is_root_key_trusted (struct cert_device_hw *hw, int root_id)
{
	struct cert_device_hw_mock *mock = (struct cert_device_hw_mock*) hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cert_device_hw_mock_is_root_key_trusted, hw, MOCK_ARG_CALL (root_id));
}

static int cert_device_hw_mock_get_minimum_key_length (struct cert_device_hw *hw,
	size_t *key_length)
{
	struct cert_device_hw_mock *mock = (struct cert_device_hw_mock*) hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cert_device_hw_mock_get_minimum_key_length, hw,
		MOCK_ARG_CALL (key_length));
}

static int cert_device_hw_mock_get_revocation (struct cert_device_hw *hw, uint32_t *id)
{
	struct cert_device_hw_mock *mock = (struct cert_device_hw_mock*) hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cert_device_hw_mock_get_revocation, hw, MOCK_ARG_CALL (id));
}

static int cert_device_hw_mock_set_revocation (struct cert_device_hw *hw, uint32_t id)
{
	struct cert_device_hw_mock *mock = (struct cert_device_hw_mock*) hw;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, cert_device_hw_mock_set_revocation, hw, MOCK_ARG_CALL (id));
}

static int cert_device_hw_mock_func_arg_count (void *func)
{
	if (func == cert_device_hw_mock_verify_root_key) {
		return 3;
	}
	else if ((func == cert_device_hw_mock_is_root_key_trusted) ||
		(func == cert_device_hw_mock_get_minimum_key_length) ||
		(func == cert_device_hw_mock_get_revocation) ||
		(func == cert_device_hw_mock_set_revocation)) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* cert_device_hw_mock_func_name_map (void *func)
{
	if (func == cert_device_hw_mock_verify_root_key) {
		return "verify_root_key";
	}
	else if (func == cert_device_hw_mock_is_root_key_trusted) {
		return "is_root_key_trusted";
	}
	else if (func == cert_device_hw_mock_get_minimum_key_length) {
		return "get_minimum_key_length";
	}
	else if (func == cert_device_hw_mock_get_revocation) {
		return "get_revocation";
	}
	else if (func == cert_device_hw_mock_set_revocation) {
		return "set_revocation";
	}
	else {
		return "unknown";
	}
}

static const char* cert_device_hw_mock_arg_name_map (void *func, int arg)
{
	if (func == cert_device_hw_mock_verify_root_key) {
		switch (arg) {
			case 0:
				return "root_key";

			case 1:
				return "key_length";

			case 2:
				return "hash";
		}
	}
	else if (func == cert_device_hw_mock_is_root_key_trusted) {
		switch (arg) {
			case 0:
				return "root_id";
		}
	}
	else if (func == cert_device_hw_mock_get_minimum_key_length) {
		switch (arg) {
			case 0:
				return "key_length";
		}
	}
	else if ((func == cert_device_hw_mock_get_revocation) ||
		(func == cert_device_hw_mock_set_revocation)) {
		switch (arg) {
			case 0:
				return "id";
		}
	}

	return "unknown";
}

/**
 * Initialize mock certificate hardware instance.
 *
 * @param mock The certificate hardware mock instance to initialize.
 *
 * @return 0 if the hardware instance was successfully initialized or an error code.
 */
int cert_device_hw_mock_init (struct cert_device_hw_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct cert_device_hw_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "cert_device_hw");

	mock->base.verify_root_key = cert_device_hw_mock_verify_root_key;
	mock->base.is_root_key_trusted = cert_device_hw_mock_is_root_key_trusted;
	mock->base.get_minimum_key_length = cert_device_hw_mock_get_minimum_key_length;
	mock->base.get_revocation = cert_device_hw_mock_get_revocation;
	mock->base.set_revocation = cert_device_hw_mock_set_revocation;

	mock->mock.func_arg_count = cert_device_hw_mock_func_arg_count;
	mock->mock.func_name_map = cert_device_hw_mock_func_name_map;
	mock->mock.arg_name_map = cert_device_hw_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a mock certificate hardware instance.
 *
 * @param mock The mock instance to release.
 */
void cert_device_hw_mock_release (struct cert_device_hw_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate that the mock was called as expected and release the instance.
 *
 * @param mock The mock instance to validate.
 *
 * @return 0 if all expectations were met or 1 if not.
 */
int cert_device_hw_mock_validate_and_release (struct cert_device_hw_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		cert_device_hw_mock_release (mock);
	}

	return status;
}
