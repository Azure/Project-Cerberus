// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "acvp_proto_interface_mock.h"


static int acvp_proto_interface_mock_init_test (const struct acvp_proto_interface *interface,
	size_t total_size)
{
	struct acvp_proto_interface_mock *mock = (struct acvp_proto_interface_mock*) interface;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, acvp_proto_interface_mock_init_test, interface,
		MOCK_ARG_CALL (total_size));
}

static int acvp_proto_interface_mock_add_test_data (const struct acvp_proto_interface *interface,
	size_t offset, const uint8_t *data, size_t length)
{
	struct acvp_proto_interface_mock *mock = (struct acvp_proto_interface_mock*) interface;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, acvp_proto_interface_mock_add_test_data, interface,
		MOCK_ARG_CALL (offset), MOCK_ARG_PTR_CALL (data), MOCK_ARG_CALL (length));
}

static int acvp_proto_interface_mock_execute_test (const struct acvp_proto_interface *interface)
{
	struct acvp_proto_interface_mock *mock = (struct acvp_proto_interface_mock*) interface;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN_NO_ARGS (&mock->mock, acvp_proto_interface_mock_execute_test, interface);
}

static int acvp_proto_interface_mock_get_test_results (const struct acvp_proto_interface *interface,
	size_t offset, uint8_t *results, size_t length)
{
	struct acvp_proto_interface_mock *mock = (struct acvp_proto_interface_mock*) interface;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, acvp_proto_interface_mock_get_test_results, interface,
		MOCK_ARG_CALL (offset), MOCK_ARG_PTR_CALL (results), MOCK_ARG_CALL (length));
}

static int acvp_proto_interface_mock_func_arg_count (void *func)
{
	if (func == acvp_proto_interface_mock_init_test) {
		return 1;
	}
	else if (func == acvp_proto_interface_mock_add_test_data) {
		return 3;
	}
	else if (func == acvp_proto_interface_mock_execute_test) {
		return 0;
	}
	else if (func == acvp_proto_interface_mock_get_test_results) {
		return 3;
	}
	else {
		return 0;
	}
}

static const char* acvp_proto_interface_mock_func_name_map (void *func)
{
	if (func == acvp_proto_interface_mock_init_test) {
		return "init_test";
	}
	else if (func == acvp_proto_interface_mock_add_test_data) {
		return "add_test_data";
	}
	else if (func == acvp_proto_interface_mock_execute_test) {
		return "execute_test";
	}
	else if (func == acvp_proto_interface_mock_get_test_results) {
		return "get_test_results";
	}
	else {
		return "unknown";
	}
}

static const char* acvp_proto_interface_mock_arg_name_map (void *func, int arg)
{
	if (func == acvp_proto_interface_mock_init_test) {
		switch (arg) {
			case 0:
				return "total_size";
		}
	}
	else if (func == acvp_proto_interface_mock_add_test_data) {
		switch (arg) {
			case 0:
				return "offset";

			case 1:
				return "data";

			case 2:
				return "length";
		}
	}
	else if (func == acvp_proto_interface_mock_get_test_results) {
		switch (arg) {
			case 0:
				return "offset";

			case 1:
				return "results";

			case 2:
				return "length";
		}
	}

	return "unknown";
}

/**
 * Initialize a mock for an ACVP Proto interface.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int acvp_proto_interface_mock_init (struct acvp_proto_interface_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct acvp_proto_interface_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "acvp_proto");

	mock->base.init_test = acvp_proto_interface_mock_init_test;
	mock->base.add_test_data = acvp_proto_interface_mock_add_test_data;
	mock->base.execute_test = acvp_proto_interface_mock_execute_test;
	mock->base.get_test_results = acvp_proto_interface_mock_get_test_results;

	mock->mock.func_arg_count = acvp_proto_interface_mock_func_arg_count;
	mock->mock.func_name_map = acvp_proto_interface_mock_func_name_map;
	mock->mock.arg_name_map = acvp_proto_interface_mock_arg_name_map;

	return 0;
}

/**
 * Release a mock ACVP Proto interface.
 *
 * @param mock The mock to release.
 */
void acvp_proto_interface_mock_release (struct acvp_proto_interface_mock *mock)
{
	if (mock != NULL) {
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
int acvp_proto_interface_mock_validate_and_release (struct acvp_proto_interface_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		acvp_proto_interface_mock_release (mock);
	}

	return status;
}
