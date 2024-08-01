// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "impactful_check_mock.h"


static int impactful_check_mock_is_not_impactful (const struct impactful_check *impactful)
{
	struct impactful_check_mock *mock = (struct impactful_check_mock*) impactful;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, impactful_check_mock_is_not_impactful, impactful);
}

static int impactful_check_mock_is_authorization_allowed (
	const struct impactful_check *impactful)
{
	struct impactful_check_mock *mock = (struct impactful_check_mock*) impactful;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, impactful_check_mock_is_authorization_allowed, impactful);
}


static int impactful_check_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* impactful_check_mock_func_name_map (void *func)
{
	if (func == impactful_check_mock_is_not_impactful) {
		return "is_not_impactful";
	}
	else if (func == impactful_check_mock_is_authorization_allowed) {
		return "is_authorization_allowed";
	}
	else {
		return "unknown";
	}
}

static const char* impactful_check_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize a mock for checking for impactful updates.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock instance was initialized successfully or an error code.
 */
int impactful_check_mock_init (struct impactful_check_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct impactful_check_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "impactful_check");

	mock->base.is_not_impactful = impactful_check_mock_is_not_impactful;
	mock->base.is_authorization_allowed = impactful_check_mock_is_authorization_allowed;

	mock->mock.func_arg_count = impactful_check_mock_func_arg_count;
	mock->mock.func_name_map = impactful_check_mock_func_name_map;
	mock->mock.arg_name_map = impactful_check_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock impactful update check.
 *
 * @param mock The mock to release.
 */
void impactful_check_mock_release (struct impactful_check_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Verify that all expected calls were executed and release the mock.
 *
 * @param mock The mock to verify.
 *
 * @return 0 if the expectations were all met or 1 if not.
 */
int impactful_check_mock_validate_and_release (struct impactful_check_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		impactful_check_mock_release (mock);
	}

	return status;
}
