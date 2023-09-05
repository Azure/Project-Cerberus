// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "security_manager_mock.h"


static int security_manager_mock_lock_device (const struct security_manager *manager)
{
	struct security_manager_mock *mock = (struct security_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, security_manager_mock_lock_device, manager);
}

static int security_manager_mock_unlock_device (const struct security_manager *manager,
	const uint8_t *policy, size_t length)
{
	struct security_manager_mock *mock = (struct security_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, security_manager_mock_unlock_device, manager,
		MOCK_ARG_PTR_CALL (policy), MOCK_ARG_CALL (length));
}

static int security_manager_mock_get_unlock_counter (const struct security_manager *manager,
	uint8_t *counter, size_t length)
{
	struct security_manager_mock *mock = (struct security_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, security_manager_mock_get_unlock_counter, manager,
		MOCK_ARG_PTR_CALL (counter), MOCK_ARG_CALL (length));
}

static int security_manager_mock_has_unlock_policy (const struct security_manager *manager)
{
	struct security_manager_mock *mock = (struct security_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, security_manager_mock_has_unlock_policy, manager);
}

static int security_manager_mock_load_security_policy (const struct security_manager *manager)
{
	struct security_manager_mock *mock = (struct security_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, security_manager_mock_load_security_policy, manager);
}

static int security_manager_mock_apply_device_config (const struct security_manager *manager)
{
	struct security_manager_mock *mock = (struct security_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, security_manager_mock_apply_device_config, manager);
}

static int security_manager_mock_get_security_policy (const struct security_manager *manager,
	const struct security_policy **policy)
{
	struct security_manager_mock *mock = (struct security_manager_mock*) manager;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, security_manager_mock_get_security_policy, manager,
		MOCK_ARG_PTR_CALL (policy));
}

static int security_manager_mock_func_arg_count (void *func)
{
	if ((func == security_manager_mock_unlock_device) ||
		(func == security_manager_mock_get_unlock_counter)) {
		return 2;
	}
	else if (func == security_manager_mock_get_security_policy) {
		return 1;
	}
	else {
		return 0;
	}
}

static const char* security_manager_mock_func_name_map (void *func)
{
	if (func == security_manager_mock_lock_device) {
		return "lock_device";
	}
	else if (func == security_manager_mock_unlock_device) {
		return "unlock_device";
	}
	else if (func == security_manager_mock_get_unlock_counter) {
		return "get_unlock_counter";
	}
	else if (func == security_manager_mock_has_unlock_policy) {
		return "has_unlock_policy";
	}
	else if (func == security_manager_mock_load_security_policy) {
		return "load_security_policy";
	}
	else if (func == security_manager_mock_apply_device_config) {
		return "apply_device_config";
	}
	else if (func == security_manager_mock_get_security_policy) {
		return "get_security_policy";
	}
	else {
		return "unknown";
	}
}

static const char* security_manager_mock_arg_name_map (void *func, int arg)
{
	if (func == security_manager_mock_unlock_device) {
		switch (arg) {
			case 0:
				return "policy";

			case 1:
				return "length";
		}
	}
	else if (func == security_manager_mock_get_unlock_counter) {
		switch (arg) {
			case 0:
				return "counter";

			case 1:
				return "length";
		}
	}
	else if (func == security_manager_mock_get_security_policy) {
		switch (arg) {
			case 0:
				return "policy";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for a security manager.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int security_manager_mock_init (struct security_manager_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct security_manager_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "security_manager");

	mock->base.lock_device = security_manager_mock_lock_device;
	mock->base.unlock_device = security_manager_mock_unlock_device;
	mock->base.get_unlock_counter = security_manager_mock_get_unlock_counter;
	mock->base.has_unlock_policy = security_manager_mock_has_unlock_policy;
	mock->base.load_security_policy = security_manager_mock_load_security_policy;
	mock->base.apply_device_config = security_manager_mock_apply_device_config;
	mock->base.internal.get_security_policy = security_manager_mock_get_security_policy;

	mock->mock.func_arg_count = security_manager_mock_func_arg_count;
	mock->mock.func_name_map = security_manager_mock_func_name_map;
	mock->mock.arg_name_map = security_manager_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by a security manager mock.
 *
 * @param mock The mock to release.
 */
void security_manager_mock_release (struct security_manager_mock *mock)
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
int security_manager_mock_validate_and_release (struct security_manager_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		security_manager_mock_release (mock);
	}

	return status;
}
