// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "device_rma_transition_mock.h"


static int device_rma_transition_mock_config_rma (const struct device_rma_transition *rma)
{
	struct device_rma_transition_mock *mock = (struct device_rma_transition_mock*) rma;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, device_rma_transition_mock_config_rma, rma);
}

static int device_rma_transition_mock_func_arg_count (void *func)
{
	return 0;
}

static const char* device_rma_transition_mock_func_name_map (void *func)
{
	if (func == device_rma_transition_mock_config_rma) {
		return "config_rma";
	}
	else {
		return "unknown";
	}
}

static const char* device_rma_transition_mock_arg_name_map (void *func, int arg)
{
	return "unknown";
}

/**
 * Initialize a mock for applying device RMA configuration.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was successfully initialized or an error code.
 */
int device_rma_transition_mock_init (struct device_rma_transition_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct device_rma_transition_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "device_rma_transition");

	mock->base.config_rma = device_rma_transition_mock_config_rma;

	mock->mock.func_arg_count = device_rma_transition_mock_func_arg_count;
	mock->mock.func_name_map = device_rma_transition_mock_func_name_map;
	mock->mock.arg_name_map = device_rma_transition_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock RMA configuration handler.
 *
 * @param mock The mock to release.
 */
void device_rma_transition_mock_release (struct device_rma_transition_mock *mock)
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
int device_rma_transition_mock_validate_and_release (struct device_rma_transition_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		device_rma_transition_mock_release (mock);
	}

	return status;
}
