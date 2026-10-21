// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "acvp_proto_tester_mock.h"


static int acvp_proto_tester_mock_check_input_length (const struct acvp_proto_tester *tester,
	size_t in_len)
{
	struct acvp_proto_tester_mock *mock = (struct acvp_proto_tester_mock*) tester;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, acvp_proto_tester_mock_check_input_length, tester,
		MOCK_ARG_CALL (in_len));
}

static int acvp_proto_tester_mock_proto_test_algo (const struct acvp_proto_tester *tester,
	const uint8_t *in, size_t in_len, uint8_t **out, size_t *out_length)
{
	struct acvp_proto_tester_mock *mock = (struct acvp_proto_tester_mock*) tester;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	MOCK_RETURN (&mock->mock, acvp_proto_tester_mock_proto_test_algo, tester,
		MOCK_ARG_PTR_CALL (in), MOCK_ARG_CALL (in_len), MOCK_ARG_PTR_CALL (out),
		MOCK_ARG_PTR_CALL (out_length));
}

// *INDENT-OFF*
MOCK_FUNCTION_TABLE_BEGIN (acvp_proto_tester, 4)
	MOCK_FUNCTION (
		acvp_proto_tester,
		check_input_length,
		1,
		MOCK_FUNCTION_ARGS ("in_len"))
	MOCK_FUNCTION (
		acvp_proto_tester,
		proto_test_algo,
		4,
		MOCK_FUNCTION_ARGS ("in", "in_len", "out", "out_length"))
MOCK_FUNCTION_TABLE_END (acvp_proto_tester)
// *INDENT-ON*

/**
 * Initialize a mock for an ACVP Proto interface.
 *
 * @param mock The mock to initialize.
 *
 * @return 0 if the mock was initialized successfully or an error code.
 */
int acvp_proto_tester_mock_init (struct acvp_proto_tester_mock *mock)
{
	int status;

	if (mock == NULL) {
		return MOCK_INVALID_ARGUMENT;
	}

	memset (mock, 0, sizeof (struct acvp_proto_tester_mock));

	status = mock_init (&mock->mock);
	if (status != 0) {
		return status;
	}

	mock_set_name (&mock->mock, "acvp_proto_tester");

	mock->base.check_input_length = acvp_proto_tester_mock_check_input_length;
	mock->base.proto_test_algo = acvp_proto_tester_mock_proto_test_algo;

	MOCK_INTERFACE_INIT (mock->mock, acvp_proto_tester);

	return 0;
}

/**
 * Release a mock ACVP Proto tester interface.
 *
 * @param mock The mock to release.
 */
void acvp_proto_tester_mock_release (struct acvp_proto_tester_mock *mock)
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
int acvp_proto_tester_mock_validate_and_release (struct acvp_proto_tester_mock *mock)
{
	int status = 1;

	if (mock != NULL) {
		status = mock_validate (&mock->mock);
		acvp_proto_tester_mock_release (mock);
	}

	return status;
}
