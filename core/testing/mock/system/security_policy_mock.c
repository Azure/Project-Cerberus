// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "security_policy_mock.h"


static int security_policy_mock_is_persistent (const struct security_policy *policy)
{
	struct security_policy_mock *mock = (struct security_policy_mock*) policy;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, security_policy_mock_is_persistent, policy);
}

static int security_policy_mock_enforce_firmware_signing (const struct security_policy *policy)
{
	struct security_policy_mock *mock = (struct security_policy_mock*) policy;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, security_policy_mock_enforce_firmware_signing, policy);
}

static int security_policy_mock_enforce_anti_rollback (const struct security_policy *policy)
{
	struct security_policy_mock *mock = (struct security_policy_mock*) policy;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, security_policy_mock_enforce_anti_rollback, policy);
}

static int security_policy_mock_check_unlock_persistence (const struct security_policy *policy,
	const uint8_t *unlock, size_t length)
{
	struct security_policy_mock *mock = (struct security_policy_mock*) policy;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, security_policy_mock_check_unlock_persistence, policy,
		MOCK_ARG_PTR_CALL (unlock), MOCK_ARG_CALL (length));
}

static int security_policy_mock_parse_unlock_policy (const struct security_policy *policy,
	const uint8_t *unlock, size_t length)
{
	struct security_policy_mock *mock = (struct security_policy_mock*) policy;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, security_policy_mock_parse_unlock_policy, policy,
		MOCK_ARG_PTR_CALL (unlock), MOCK_ARG_CALL (length));
}

static int security_policy_mock_func_arg_count (void *func)
{
	if ((func == security_policy_mock_check_unlock_persistence) ||
		(func == security_policy_mock_parse_unlock_policy)) {
		return 2;
	}
	else {
		return 0;
	}
}

static const char* security_policy_mock_func_name_map (void *func)
{
	if (func == security_policy_mock_is_persistent) {
		return "is_persistent";
	}
	else if (func == security_policy_mock_enforce_firmware_signing) {
		return "enforce_firmware_signing";
	}
	else if (func == security_policy_mock_enforce_anti_rollback) {
		return "enforce_anti_rollback";
	}
	else if (func == security_policy_mock_check_unlock_persistence) {
		return "check_unlock_persistence";
	}
	else if (func == security_policy_mock_parse_unlock_policy) {
		return "parse_unlock_policy";
	}
	else {
		return "unknown";
	}
}

static const char* security_policy_mock_arg_name_map (void *func, int arg)
{
	if (func == security_policy_mock_check_unlock_persistence) {
		switch (arg) {
			case 0:
				return "unlock";

			case 1:
				return "length";
		}
	}
	else if (func == security_policy_mock_parse_unlock_policy) {
		switch (arg) {
			case 0:
				return "unlock";

			case 1:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a device security policy.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int security_policy_mock_init (struct security_policy_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct security_policy_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "security_policy");

	mock->base.is_persistent = security_policy_mock_is_persistent;
	mock->base.enforce_firmware_signing = security_policy_mock_enforce_firmware_signing;
	mock->base.enforce_anti_rollback = security_policy_mock_enforce_anti_rollback;
	mock->base.check_unlock_persistence = security_policy_mock_check_unlock_persistence;
	mock->base.parse_unlock_policy = security_policy_mock_parse_unlock_policy;

	mock->mock.func_arg_count = security_policy_mock_func_arg_count;
	mock->mock.func_name_map = security_policy_mock_func_name_map;
	mock->mock.arg_name_map = security_policy_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a security policy mock.
 *
 * @param mock The mock to release.
 */
void security_policy_mock_release (struct security_policy_mock *mock)
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
int security_policy_mock_validate_and_release (struct security_policy_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		security_policy_mock_release (mock);
	}

	return status;
}
