// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "secure_device_unlock_mock.h"


static int secure_device_unlock_mock_get_unlock_token (const struct secure_device_unlock *unlock,
	uint8_t *token, size_t length)
{
	struct secure_device_unlock_mock *mock = (struct secure_device_unlock_mock*) unlock;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, secure_device_unlock_mock_get_unlock_token, unlock,
		MOCK_ARG_PTR_CALL (token), MOCK_ARG_CALL (length));
}

static int secure_device_unlock_mock_apply_unlock_policy (const struct secure_device_unlock *unlock,
	const uint8_t *policy, size_t length)
{
	struct secure_device_unlock_mock *mock = (struct secure_device_unlock_mock*) unlock;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, secure_device_unlock_mock_apply_unlock_policy, unlock,
		MOCK_ARG_PTR_CALL (policy), MOCK_ARG_CALL (length));
}

static int secure_device_unlock_mock_clear_unlock_policy (const struct secure_device_unlock *unlock)
{
	struct secure_device_unlock_mock *mock = (struct secure_device_unlock_mock*) unlock;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, secure_device_unlock_mock_clear_unlock_policy, unlock);
}

static int secure_device_unlock_mock_func_arg_count (void *func)
{
	if ((func == secure_device_unlock_mock_get_unlock_token) ||
		(func == secure_device_unlock_mock_apply_unlock_policy)) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* secure_device_unlock_mock_func_name_map (void *func)
{
	if (func == secure_device_unlock_mock_get_unlock_token) {
		return "get_unlock_token";
	}
	else if (func == secure_device_unlock_mock_apply_unlock_policy) {
		return "apply_unlock_policy";
	}
	else if (func == secure_device_unlock_mock_clear_unlock_policy) {
		return "clear_unlock_policy";
	}
	else {
		return "unknown";
	}
}

static const char* secure_device_unlock_mock_arg_name_map (void *func, int arg)
{
	if (func == secure_device_unlock_mock_get_unlock_token) {
		switch (arg) {
			case 0:
				return "token";

			case 1:
				return "length";
		}
	}
	else if (func == secure_device_unlock_mock_apply_unlock_policy) {
		switch (arg) {
			case 0:
				return "policy";

			case 1:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a secure unlock handler.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int secure_device_unlock_mock_init (struct secure_device_unlock_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct secure_device_unlock_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "secure_device_unlock");

	mock->base.get_unlock_token = secure_device_unlock_mock_get_unlock_token;
	mock->base.apply_unlock_policy = secure_device_unlock_mock_apply_unlock_policy;
	mock->base.clear_unlock_policy = secure_device_unlock_mock_clear_unlock_policy;

	mock->mock.func_arg_count = secure_device_unlock_mock_func_arg_count;
	mock->mock.func_name_map = secure_device_unlock_mock_func_name_map;
	mock->mock.arg_name_map = secure_device_unlock_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a security policy manager mock.
 *
 * @param mock The mock to release.
 */
void secure_device_unlock_mock_release (struct secure_device_unlock_mock *mock)
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
int secure_device_unlock_mock_validate_and_release (struct secure_device_unlock_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		secure_device_unlock_mock_release (mock);
	}

	return status;
}
