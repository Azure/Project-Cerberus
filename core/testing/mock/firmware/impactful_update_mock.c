// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "impactful_update_mock.h"


static int impactful_update_mock_is_update_not_impactful (
	const struct impactful_update_interface *impactful)
{
	struct impactful_update_mock *mock = (struct impactful_update_mock*) impactful;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, impactful_update_mock_is_update_not_impactful, impactful);
}

static int impactful_update_mock_is_update_allowed (
	const struct impactful_update_interface *impactful)
{
	struct impactful_update_mock *mock = (struct impactful_update_mock*) impactful;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, impactful_update_mock_is_update_allowed, impactful);
}

static int impactful_update_mock_authorize_update (
	const struct impactful_update_interface *impactful, uint32_t allowed_time_ms)
{
	struct impactful_update_mock *mock = (struct impactful_update_mock*) impactful;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, impactful_update_mock_authorize_update, impactful,
		MOCK_ARG_CALL (allowed_time_ms));
}

static int impactful_update_mock_reset_authorization (
	const struct impactful_update_interface *impactful)
{
	struct impactful_update_mock *mock = (struct impactful_update_mock*) impactful;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, impactful_update_mock_reset_authorization, impactful);
}

static int impactful_update_mock_func_arg_count (void *func)
{
	if (func == impactful_update_mock_authorize_update) {
		return 1;
	}

	return 0;
}

static const char* impactful_update_mock_func_name_map (void *func)
{
	if (func == impactful_update_mock_is_update_not_impactful) {
		return "is_update_not_impactful";
	}
	else if (func == impactful_update_mock_is_update_allowed) {
		return "is_update_allowed";
	}
	else if (func == impactful_update_mock_authorize_update) {
		return "authorize_update";
	}
	else if (func == impactful_update_mock_reset_authorization) {
		return "reset_authorization";
	}
	else {
		return "unknown";
	}
}

static const char* impactful_update_mock_arg_name_map (void *func, int arg)
{
	if (func == impactful_update_mock_authorize_update) {
		switch (arg) {
			case 0:
				return "allowed_time_ms";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a impactful update interface.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock instance was initialized successfully or an error code.
 */
int impactful_update_mock_init (struct impactful_update_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct impactful_update_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "impactful_update");

	mock->base.is_update_not_impactful = impactful_update_mock_is_update_not_impactful;
	mock->base.is_update_allowed = impactful_update_mock_is_update_allowed;
	mock->base.authorize_update = impactful_update_mock_authorize_update;
	mock->base.reset_authorization = impactful_update_mock_reset_authorization;

	mock->mock.func_arg_count = impactful_update_mock_func_arg_count;
	mock->mock.func_name_map = impactful_update_mock_func_name_map;
	mock->mock.arg_name_map = impactful_update_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock impactful update handler.
 *
 * @param mock The mock to release.
 */
void impactful_update_mock_release (struct impactful_update_mock *mock)
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
int impactful_update_mock_validate_and_release (struct impactful_update_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		impactful_update_mock_release (mock);
	}

	return status;
}
