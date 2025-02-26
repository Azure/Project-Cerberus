// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_proto_static.h"
#include "testing/acvp/acvp_testing.h"
#include "testing/mock/acvp/acvp_proto_tester_mock.h"


TEST_SUITE_LABEL ("acvp_proto");


/**
 * Dependencies for testing ACVP Proto.
 */
struct acvp_proto_testing {
	struct acvp_proto test;						/**< ACVP Proto instance. */
	struct acvp_proto_state state;				/**< ACVP Proto variable context. */
	struct acvp_proto_tester_mock tester_mock;	/**< ACVP Proto tester mock. */
};


/**
 * Initialize dependencies for testing ACVP Proto.
 *
 * @param test The test framework.
 * @param acvp The ACVP Proto testing dependencies.
 */
static void acvp_proto_testing_init_dependencies (CuTest *test, struct acvp_proto_testing *acvp)
{
	int status;

	status = acvp_proto_tester_mock_init (&acvp->tester_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release dependencies for ACVP Proto testing and validate mocks.
 *
 * @param test The test framework.
 * @param acvp The ACVP Proto testing dependencies.
 */
static void acvp_proto_testing_release_dependencies (CuTest *test, struct acvp_proto_testing *acvp)
{
	int status;

	status = acvp_proto_tester_mock_validate_and_release (&acvp->tester_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize the ACVP Proto testing instance.
 *
 * @param test The test framework.
 * @param acvp The ACVP Proto testing instance to initialize.
 */
static void acvp_proto_testing_init (CuTest *test, struct acvp_proto_testing *acvp)
{
	int status;

	acvp_proto_testing_init_dependencies (test, acvp);

	status = acvp_proto_init (&acvp->test, &acvp->state, &acvp->tester_mock.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static instance for testing.
 *
 * @param test The test framework.
 * @param acvp The ACVP Proto testing dependencies.
 */
static void acvp_proto_testing_init_static (CuTest *test, struct acvp_proto_testing *acvp)
{
	int status;

	acvp_proto_testing_init_dependencies (test, acvp);

	status = acvp_proto_init_state (&acvp->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release the ACVP Proto testing instance.
 *
 * @param test The test framework.
 * @param acvp The ACVP Proto testing instance to release.
 */
static void acvp_proto_testing_release (CuTest *test, struct acvp_proto_testing *acvp)
{
	acvp_proto_release (&acvp->test);

	acvp_proto_testing_release_dependencies (test, acvp);
}


/*******************
 * Test cases
 *******************/

static void acvp_proto_test_init (CuTest *test)
{
	struct acvp_proto acvp;
	struct acvp_proto_state state;
	struct acvp_proto_tester tester;
	int status;

	TEST_START;

	status = acvp_proto_init (&acvp, &state, &tester);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, acvp.base.init_test);
	CuAssertPtrNotNull (test, acvp.base.add_test_data);
	CuAssertPtrNotNull (test, acvp.base.execute_test);
	CuAssertPtrNotNull (test, acvp.base.get_test_results);

	acvp_proto_release (&acvp);
}

static void acvp_proto_test_init_null (CuTest *test)
{
	struct acvp_proto acvp;
	struct acvp_proto_state state;
	struct acvp_proto_tester tester;
	int status;

	TEST_START;

	status = acvp_proto_init (NULL, &state, &tester);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	status = acvp_proto_init (&acvp, NULL, &tester);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	status = acvp_proto_init (&acvp, &state, NULL);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);
}

static void acvp_proto_test_static_init (CuTest *test)
{
	struct acvp_proto_testing acvp = {
		.test = acvp_proto_static_init (&acvp.state, &acvp.tester_mock.base)
	};
	int status;

	TEST_START;

	acvp_proto_testing_init_dependencies (test, &acvp);

	CuAssertPtrNotNull (test, acvp.test.base.init_test);
	CuAssertPtrNotNull (test, acvp.test.base.add_test_data);
	CuAssertPtrNotNull (test, acvp.test.base.execute_test);
	CuAssertPtrNotNull (test, acvp.test.base.get_test_results);

	status = acvp_proto_init_state (&acvp.test);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_static_init_null (CuTest *test)
{
	struct acvp_proto_testing acvp1;
	struct acvp_proto_testing acvp2;
	struct acvp_proto acvp_null_state = acvp_proto_static_init (NULL, &acvp1.tester_mock.base);
	struct acvp_proto acvp_null_tester = acvp_proto_static_init (&acvp2.state, NULL);
	int status;

	TEST_START;

	acvp_proto_testing_init_dependencies (test, &acvp1);
	acvp_proto_testing_init_dependencies (test, &acvp2);

	status = acvp_proto_init_state (&acvp_null_state);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	status = acvp_proto_init_state (&acvp_null_tester);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	status = acvp_proto_init_state (NULL);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);
}

static void acvp_proto_test_release_null (CuTest *test)
{
	TEST_START;

	acvp_proto_release (NULL);
}

static void acvp_proto_test_init_test (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	size_t total_size = 0x434;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_init_test_static_init (CuTest *test)
{
	struct acvp_proto_testing acvp = {
		.test = acvp_proto_static_init (&acvp.state, &acvp.tester_mock.base)
	};
	int status;
	size_t total_size = 0x521;

	TEST_START;

	acvp_proto_testing_init_static (test, &acvp);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_init_test_null (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	size_t total_size = 0x12345678;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = acvp.test.base.init_test (NULL, total_size);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_init_test_too_small (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	size_t total_size = 1;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, ACVP_PROTO_TESTER_LENGTH_TOO_SMALL, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_LENGTH_TOO_SMALL, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_add_test_data (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA512_LEN + 30;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, ACVP_PROTO_TEST_DATA_SHA512,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_add_test_data_overwrite_data (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA512_LEN + 40;
	size_t offset = 0;
	size_t offset2 = 20;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, offset, ACVP_PROTO_TEST_DATA_SHA512,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, offset2, ACVP_PROTO_TEST_DATA_SHA512,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_add_test_data_static_init (CuTest *test)
{
	struct acvp_proto_testing acvp = {
		.test = acvp_proto_static_init (&acvp.state, &acvp.tester_mock.base)
	};
	int status;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA512_LEN + 20;

	TEST_START;

	acvp_proto_testing_init_static (test, &acvp);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, ACVP_PROTO_TEST_DATA_SHA512,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_add_test_data_null (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = acvp.test.base.add_test_data (NULL, 0, ACVP_PROTO_TEST_DATA_SHA512,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, NULL,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_add_test_data_invalid_state (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	// Attempt to add test data prior to initializing the test
	status = acvp.test.base.add_test_data (&acvp.test.base, 0, ACVP_PROTO_TEST_DATA_SHA512,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_STATE, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_add_test_data_invalid_offset (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA512_LEN + 10;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, SIZE_MAX, ACVP_PROTO_TEST_DATA_SHA512,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, ACVP_PROTO_ADD_TEST_DATA_OFFSET_OUT_OF_RANGE, status);

	status = acvp.test.base.add_test_data (&acvp.test.base,
		total_size - ACVP_PROTO_TEST_DATA_SHA512_LEN + 1, ACVP_PROTO_TEST_DATA_SHA512,
		ACVP_PROTO_TEST_DATA_SHA512_LEN);
	CuAssertIntEquals (test, ACVP_PROTO_ADD_TEST_DATA_OFFSET_OUT_OF_RANGE, status);

	// Check for length + offset overflow
	status = acvp.test.base.add_test_data (&acvp.test.base,	1, ACVP_PROTO_TEST_DATA_SHA512,
		SIZE_MAX);
	CuAssertIntEquals (test, ACVP_PROTO_ADD_TEST_DATA_OFFSET_OUT_OF_RANGE, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_execute_test (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	const uint8_t *test_data = ACVP_PROTO_TEST_DATA_SHA256;
	uint8_t *results;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA256_LEN;
	size_t results_len = ACVP_PROTO_TEST_RESULTS_SHA256_LEN;
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	results = platform_malloc (results_len);
	CuAssertPtrNotNull (test, results);

	memcpy (results, ACVP_PROTO_TEST_RESULTS_SHA256, results_len);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.proto_test_algo,
		&acvp.tester_mock, 0, MOCK_ARG_PTR_CONTAINS (test_data, sizeof (test_data)),
		MOCK_ARG (total_size), MOCK_ARG_PTR_PTR (NULL),	MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&acvp.tester_mock.mock, 2, &results, sizeof (results), -1);
	status |= mock_expect_output (&acvp.tester_mock.mock, 3, &results_len, sizeof (size_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, test_data, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.execute_test (&acvp.test.base, &results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len, results_length);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_execute_test_static_init (CuTest *test)
{
	struct acvp_proto_testing acvp = {
		.test = acvp_proto_static_init (&acvp.state, &acvp.tester_mock.base)
	};
	int status;
	const uint8_t *test_data = ACVP_PROTO_TEST_DATA_SHA512;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA512_LEN;
	uint8_t *results;
	size_t results_len = ACVP_PROTO_TEST_RESULTS_SHA512_LEN;
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init_static (test, &acvp);

	results = platform_malloc (results_len);
	CuAssertPtrNotNull (test, results);

	memcpy (results, ACVP_PROTO_TEST_RESULTS_SHA512, results_len);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.proto_test_algo,
		&acvp.tester_mock, 0, MOCK_ARG_PTR_CONTAINS (test_data, sizeof (test_data)),
		MOCK_ARG (total_size), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&acvp.tester_mock.mock, 2, &results, sizeof (results), -1);
	status |= mock_expect_output (&acvp.tester_mock.mock, 3, &results_len, sizeof (size_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, test_data, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.execute_test (&acvp.test.base, &results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len, results_length);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_execute_test_invalid_state (CuTest *test)
{
	struct acvp_proto_testing acvp;
	size_t results_length;
	int status;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	// Attempt to execute a test prior to initializing the test
	status = acvp.test.base.execute_test (&acvp.test.base, &results_length);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_STATE, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_execute_test_tester_error (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	const uint8_t *test_data = ACVP_PROTO_TEST_DATA_SHA256;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA256_LEN;
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.proto_test_algo,
		&acvp.tester_mock, ACVP_PROTO_TESTER_TEST_FAILED,
		MOCK_ARG_PTR_CONTAINS (test_data, sizeof (test_data)), MOCK_ARG (total_size),
		MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, test_data, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.execute_test (&acvp.test.base, &results_length);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_TEST_FAILED, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_execute_test_null (CuTest *test)
{
	struct acvp_proto_testing acvp;
	size_t results_length;
	int status;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = acvp.test.base.execute_test (NULL, &results_length);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	status = acvp.test.base.execute_test (&acvp.test.base, NULL);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_get_test_results (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	const uint8_t *test_data = ACVP_PROTO_TEST_DATA_SHA256;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA256_LEN;
	uint8_t *expected_results;
	size_t results_len = ACVP_PROTO_TEST_RESULTS_SHA256_LEN;
	uint8_t results[results_len];
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	expected_results = platform_malloc (results_len);
	CuAssertPtrNotNull (test, expected_results);

	memcpy (expected_results, ACVP_PROTO_TEST_RESULTS_SHA256, results_len);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.proto_test_algo,
		&acvp.tester_mock, 0, MOCK_ARG_PTR_CONTAINS (test_data, sizeof (test_data)),
		MOCK_ARG (total_size), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&acvp.tester_mock.mock, 2, &expected_results,
		sizeof (expected_results), -1);
	status |= mock_expect_output (&acvp.tester_mock.mock, 3, &results_len, sizeof (size_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, test_data, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.execute_test (&acvp.test.base, &results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len, results_length);

	status = acvp.test.base.get_test_results (&acvp.test.base, 0, results, results_len,
		&results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len, results_length);

	status = testing_validate_array (ACVP_PROTO_TEST_RESULTS_SHA256, results, results_len);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_get_test_results_multiple_reads (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	const uint8_t *test_data = ACVP_PROTO_TEST_DATA_SHA384;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA384_LEN;
	uint8_t *expected_results;
	size_t results_len = ACVP_PROTO_TEST_RESULTS_SHA384_LEN;
	uint8_t results[results_len];
	size_t offset = 0;
	size_t offset2 = results_len - 10;
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	expected_results = platform_malloc (results_len);
	CuAssertPtrNotNull (test, expected_results);

	memcpy (expected_results, ACVP_PROTO_TEST_RESULTS_SHA384, results_len);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.proto_test_algo,
		&acvp.tester_mock, 0, MOCK_ARG_PTR_CONTAINS (test_data, sizeof (test_data)),
		MOCK_ARG (total_size), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&acvp.tester_mock.mock, 2, &expected_results,
		sizeof (expected_results), -1);
	status |= mock_expect_output (&acvp.tester_mock.mock, 3, &results_len, sizeof (size_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, test_data, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.execute_test (&acvp.test.base, &results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len, results_length);

	// Read a partial set of results
	status = acvp.test.base.get_test_results (&acvp.test.base, offset, results, offset2,
		&results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, offset2, results_length);

	// Read same data again
	status = acvp.test.base.get_test_results (&acvp.test.base, offset, results, offset2,
		&results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, offset2, results_length);

	// Read data with overlap into previous read
	status = acvp.test.base.get_test_results (&acvp.test.base, offset2 - 1, &results[offset2 - 1],
		results_len, &results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len - offset2 + 1, results_length);

	status = testing_validate_array (ACVP_PROTO_TEST_RESULTS_SHA384, results, results_len);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_get_test_results_offset_out_of_bounds (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	const uint8_t *test_data = ACVP_PROTO_TEST_DATA_SHA384;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA384_LEN;
	uint8_t *results;
	size_t results_len = ACVP_PROTO_TEST_RESULTS_SHA384_LEN;
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	results = platform_malloc (results_len);
	CuAssertPtrNotNull (test, results);

	memcpy (results, ACVP_PROTO_TEST_RESULTS_SHA384, results_len);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.proto_test_algo,
		&acvp.tester_mock, 0, MOCK_ARG_PTR_CONTAINS (test_data, sizeof (test_data)),
		MOCK_ARG (total_size), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&acvp.tester_mock.mock, 2, &results, sizeof (results), -1);
	status |= mock_expect_output (&acvp.tester_mock.mock, 3, &results_len, sizeof (size_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, test_data, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.execute_test (&acvp.test.base, &results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len, results_length);

	// Requests for offsets lying outside of the buffer are valid, but return no data.
	status = acvp.test.base.get_test_results (&acvp.test.base, results_len + 1, results,
		results_len, &results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, results_length);

	status = acvp.test.base.get_test_results (&acvp.test.base, SIZE_MAX, results, results_len,
		&results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, results_length);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_get_test_results_static_init (CuTest *test)
{
	struct acvp_proto_testing acvp = {
		.test = acvp_proto_static_init (&acvp.state, &acvp.tester_mock.base)
	};
	int status;
	const uint8_t *test_data = ACVP_PROTO_TEST_DATA_SHA512;
	size_t total_size = ACVP_PROTO_TEST_DATA_SHA512_LEN;
	uint8_t *expected_results;
	size_t results_len = ACVP_PROTO_TEST_RESULTS_SHA512_LEN;
	uint8_t results[results_len];
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init_static (test, &acvp);

	expected_results = platform_malloc (results_len);
	CuAssertPtrNotNull (test, expected_results);

	memcpy (expected_results, ACVP_PROTO_TEST_RESULTS_SHA512, results_len);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.check_input_length,
		&acvp.tester_mock, 0, MOCK_ARG (total_size));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&acvp.tester_mock.mock, acvp.tester_mock.base.proto_test_algo,
		&acvp.tester_mock, 0, MOCK_ARG_PTR_CONTAINS (test_data, sizeof (test_data)),
		MOCK_ARG (total_size), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&acvp.tester_mock.mock, 2, &expected_results,
		sizeof (expected_results), -1);
	status |= mock_expect_output (&acvp.tester_mock.mock, 3, &results_len, sizeof (size_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.init_test (&acvp.test.base, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.add_test_data (&acvp.test.base, 0, test_data, total_size);
	CuAssertIntEquals (test, 0, status);

	status = acvp.test.base.execute_test (&acvp.test.base, &results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len, results_length);

	status = acvp.test.base.get_test_results (&acvp.test.base, 0, results, sizeof (results),
		&results_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, results_len, results_length);

	status = testing_validate_array (ACVP_PROTO_TEST_RESULTS_SHA512, results, results_len);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_get_test_results_null (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	size_t offset = 0;
	uint8_t results[ACVP_PROTO_TEST_RESULTS_SHA512_LEN];
	size_t length = sizeof (results);
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	status = acvp.test.base.get_test_results (NULL, offset, results, length, &results_length);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	status = acvp.test.base.get_test_results (&acvp.test.base, offset, NULL, length,
		&results_length);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	status = acvp.test.base.get_test_results (&acvp.test.base, offset, results, length, NULL);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_ARGUMENT, status);

	acvp_proto_testing_release (test, &acvp);
}

static void acvp_proto_test_get_test_results_invalid_state (CuTest *test)
{
	struct acvp_proto_testing acvp;
	int status;
	uint8_t results[ACVP_PROTO_TEST_RESULTS_SHA512_LEN];
	size_t length = sizeof (results);
	size_t results_length;

	TEST_START;

	acvp_proto_testing_init (test, &acvp);

	// Attempt to get test results prior to initializing the test
	status = acvp.test.base.get_test_results (&acvp.test.base, 0, results, length, &results_length);
	CuAssertIntEquals (test, ACVP_PROTO_INVALID_STATE, status);

	acvp_proto_testing_release (test, &acvp);
}


// *INDENT-OFF*
TEST_SUITE_START (acvp_proto);

TEST (acvp_proto_test_init);
TEST (acvp_proto_test_init_null);
TEST (acvp_proto_test_static_init);
TEST (acvp_proto_test_static_init_null);
TEST (acvp_proto_test_release_null);
TEST (acvp_proto_test_init_test);
TEST (acvp_proto_test_init_test_static_init);
TEST (acvp_proto_test_init_test_null);
TEST (acvp_proto_test_init_test_too_small);
TEST (acvp_proto_test_add_test_data);
TEST (acvp_proto_test_add_test_data_overwrite_data);
TEST (acvp_proto_test_add_test_data_static_init);
TEST (acvp_proto_test_add_test_data_null);
TEST (acvp_proto_test_add_test_data_invalid_state);
TEST (acvp_proto_test_add_test_data_invalid_offset);
TEST (acvp_proto_test_execute_test);
TEST (acvp_proto_test_execute_test_static_init);
TEST (acvp_proto_test_execute_test_invalid_state);
TEST (acvp_proto_test_execute_test_tester_error);
TEST (acvp_proto_test_execute_test_null);
TEST (acvp_proto_test_get_test_results);
TEST (acvp_proto_test_get_test_results_multiple_reads);
TEST (acvp_proto_test_get_test_results_offset_out_of_bounds);
TEST (acvp_proto_test_get_test_results_static_init);
TEST (acvp_proto_test_get_test_results_null);
TEST (acvp_proto_test_get_test_results_invalid_state);

TEST_SUITE_END;
// *INDENT-ON*
