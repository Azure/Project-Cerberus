// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "ocp_recovery_device_variable_cms_mock.h"


static int ocp_recovery_device_variable_cms_mock_get_size (
	const struct ocp_recovery_device_variable_cms *cms)
{
	struct ocp_recovery_device_variable_cms_mock *mock =
		(struct ocp_recovery_device_variable_cms_mock*) cms;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, ocp_recovery_device_variable_cms_mock_get_size, cms);
}

static int ocp_recovery_device_variable_cms_mock_get_data (
	const struct ocp_recovery_device_variable_cms *cms, size_t offset, uint8_t *data, size_t length)
{
	struct ocp_recovery_device_variable_cms_mock *mock =
		(struct ocp_recovery_device_variable_cms_mock*) cms;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, ocp_recovery_device_variable_cms_mock_get_data, cms,
		MOCK_ARG_CALL (offset), MOCK_ARG_CALL (data), MOCK_ARG_CALL (length));
}

static int ocp_recovery_device_variable_cms_mock_func_arg_count (void *func)
{
	if (func == ocp_recovery_device_variable_cms_mock_get_data) {
		return 3;
	}
	else {
		return 0;
	}
}

static const char* ocp_recovery_device_variable_cms_mock_func_name_map (void *func)
{
	if (func == ocp_recovery_device_variable_cms_mock_get_size) {
		return "get_size";
	}
	else if (func == ocp_recovery_device_variable_cms_mock_get_data) {
		return "get_data";
	}
	else {
		return "unknown";
	}
}

static const char* ocp_recovery_device_variable_cms_mock_arg_name_map (void *func, int arg)
{
	if (func == ocp_recovery_device_variable_cms_mock_get_data) {
		switch (arg) {
			case 0:
				return "offset";

			case 1:
				return "data";

			case 2:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock instance for a OCP Recovery variable CMS.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int ocp_recovery_device_variable_cms_mock_init (struct ocp_recovery_device_variable_cms_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct ocp_recovery_device_variable_cms_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "ocp_recovery_device_variable_cms");

	mock->base.get_size = ocp_recovery_device_variable_cms_mock_get_size;
	mock->base.get_data = ocp_recovery_device_variable_cms_mock_get_data;

	mock->mock.func_arg_count = ocp_recovery_device_variable_cms_mock_func_arg_count;
	mock->mock.func_name_map = ocp_recovery_device_variable_cms_mock_func_name_map;
	mock->mock.arg_name_map = ocp_recovery_device_variable_cms_mock_arg_name_map;

	return 0;
}

/**
 * Release the resources used by the mock API.
 *
 * @param mock The mock to release.
 */
void ocp_recovery_device_variable_cms_mock_release (
	struct ocp_recovery_device_variable_cms_mock *mock)
{
	if (mock != NULL) {
		mock_release (&mock->mock);
	}
}

/**
 * Validate all mock expectations were called and release the mock instance.
 *
 * @param mock The mock to validate.
 *
 * @return 0 if the expectations were met or 1 if not.
 */
int ocp_recovery_device_variable_cms_mock_validate_and_release (
	struct ocp_recovery_device_variable_cms_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		ocp_recovery_device_variable_cms_mock_release (mock);
	}

	return status;
}
