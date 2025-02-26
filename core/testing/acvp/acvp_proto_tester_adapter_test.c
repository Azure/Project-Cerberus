// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "acvp/acvp_proto_tester_adapter_static.h"
#include "backend_interfaces/protobuf/backend_protobuf.h"
#include "parser/common.h"


TEST_SUITE_LABEL ("acvp_proto_tester_adapter");


/**
 * ACVP test input data to use for SHA256 testing.
 */
const uint8_t ACVP_PROTO_TEST_DATA_SHA256[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0A, 0x11, 0x9C, 0x08, 0xA0, 0xF1, 0x70, 0x30,
	0x21, 0x38, 0x69, 0x16, 0x92, 0x4A, 0xD7, 0x51,
	0xD2, 0x64, 0x15, 0x10, 0x88, 0x01, 0x40, 0x80,
	0x80, 0x8C, 0x80, 0x80, 0x80, 0x80, 0x04
};

/**
 * Length of the SHA256 ACVP test input data.
 */
const size_t ACVP_PROTO_TEST_DATA_SHA256_LEN = sizeof (ACVP_PROTO_TEST_DATA_SHA256);

/**
 * ACVP test input data to use for SHA384 testing.
 */
const uint8_t ACVP_PROTO_TEST_DATA_SHA384[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0A, 0x11, 0x9C, 0x08, 0xA0, 0xF1, 0x70, 0x30,
	0x21, 0x38, 0x69, 0x16, 0x92, 0x4A, 0xD7, 0x51,
	0xD2, 0x64, 0x15, 0x10, 0x88, 0x01, 0x40, 0x80,
	0x80, 0x90, 0x80, 0x80, 0x80, 0x80, 0x04
};

/**
 * Length of the SHA384 ACVP test input data.
 */
const size_t ACVP_PROTO_TEST_DATA_SHA384_LEN = sizeof (ACVP_PROTO_TEST_DATA_SHA384);

/**
 * ACVP test input data to use for SHA512 testing.
 */
const uint8_t ACVP_PROTO_TEST_DATA_SHA512[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x0A, 0x11, 0x9C, 0x08, 0xA0, 0xF1, 0x70, 0x30,
	0x21, 0x38, 0x69, 0x16, 0x92, 0x4A, 0xD7, 0x51,
	0xD2, 0x64, 0x15, 0x10, 0x88, 0x01, 0x40, 0x80,
	0x80, 0x94, 0x80, 0x80, 0x80, 0x80, 0x04
};

/**
 * Length of the SHA512 ACVP test input data.
 */
const size_t ACVP_PROTO_TEST_DATA_SHA512_LEN = sizeof (ACVP_PROTO_TEST_DATA_SHA512);

/**
 * Expected ACVP test output for SHA256 operation on ACVP_PROTO_TEST_DATA.
 */
const uint8_t ACVP_PROTO_TEST_RESULTS_SHA256[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x3A, 0x20, 0xCC, 0x44, 0x1D, 0x7F, 0x5D, 0x14,
	0x02, 0x12, 0xB1, 0x29, 0x18, 0xDC, 0x0D, 0x88,
	0xA9, 0x9D, 0x7E, 0x9E, 0x7C, 0xDD, 0x49, 0xA1,
	0xC5, 0x9E, 0xB6, 0x64, 0x6D, 0xC5, 0x26, 0x38,
	0xC0, 0x91
};

/**
 * Length of the ACVP test output for SHA256 operation on ACVP_PROTO_TEST_DATA.
 */
const size_t ACVP_PROTO_TEST_RESULTS_SHA256_LEN = sizeof (ACVP_PROTO_TEST_RESULTS_SHA256);

/**
 * Expected ACVP test output for SHA384 operation on ACVP_PROTO_TEST_DATA.
 */
const uint8_t ACVP_PROTO_TEST_RESULTS_SHA384[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x32, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x3A, 0x30, 0x15, 0x53, 0xCB, 0x32, 0xAC, 0x1B,
	0x2E, 0xE1, 0x5F, 0x2D, 0x9D, 0x25, 0x32, 0xDB,
	0x08, 0xF8, 0x91, 0xEF, 0x8F, 0x06, 0x95, 0xCA,
	0x37, 0xB4, 0xC9, 0x14, 0x4B, 0xAD, 0x9E, 0xAC,
	0x9B, 0x3A, 0x59, 0x64, 0x1C, 0x80, 0x29, 0x2F,
	0xBE, 0xC3, 0x3E, 0x5C, 0x43, 0x09, 0xDB, 0x45,
	0xD6, 0x03
};

/**
 * Length of the ACVP test output for SHA384 operation on ACVP_PROTO_TEST_DATA.
 */
const size_t ACVP_PROTO_TEST_RESULTS_SHA384_LEN = sizeof (ACVP_PROTO_TEST_RESULTS_SHA384);

/**
 * Expected ACVP test output for SHA512 operation on ACVP_PROTO_TEST_DATA.
 */
const uint8_t ACVP_PROTO_TEST_RESULTS_SHA512[] = {
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x3A, 0x40, 0x7B, 0x23, 0xDB, 0x80, 0x83, 0x9C,
	0x6C, 0x65, 0xA2, 0x41, 0x20, 0x32, 0x9C, 0x6E,
	0xC8, 0x41, 0x1E, 0x6E, 0x64, 0x0A, 0x32, 0x61,
	0xA0, 0xCB, 0x9B, 0x76, 0x71, 0x7C, 0xB4, 0x6C,
	0x8D, 0x08, 0x9D, 0x76, 0x40, 0x7B, 0x92, 0x37,
	0xA4, 0x07, 0x14, 0x2B, 0x4B, 0x46, 0x6E, 0xE2,
	0x5B, 0xFF, 0xB4, 0x59, 0x7A, 0xE0, 0xE1, 0xE4,
	0x51, 0x28, 0x90, 0xD0, 0xF1, 0x9D, 0x6A, 0x43,
	0x6B, 0x6D
};

/**
 * Length of the ACVP test output for SHA512 operation on ACVP_PROTO_TEST_DATA.
 */
const size_t ACVP_PROTO_TEST_RESULTS_SHA512_LEN = sizeof (ACVP_PROTO_TEST_RESULTS_SHA512);


/*******************
 * Test cases
 *******************/

static void acvp_proto_tester_adapter_test_init (CuTest *test)
{
	struct acvp_proto_tester_adapter adapter;
	int status;

	TEST_START;

	status = acvp_proto_tester_adapter_init (&adapter);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, adapter.base.check_input_length);
	CuAssertPtrNotNull (test, adapter.base.proto_test_algo);

	acvp_proto_tester_adapter_release (&adapter);
}

static void acvp_proto_tester_adapter_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = acvp_proto_tester_adapter_init (NULL);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_INVALID_ARGUMENT, status);
}

static void acvp_proto_tester_dapter_test_check_input_length (CuTest *test)
{
	struct acvp_proto_tester_adapter adapter;
	int status;
	size_t in_len = PB_BUF_WRITE_HEADER_SZ + 20;

	TEST_START;

	status = acvp_proto_tester_adapter_init (&adapter);
	CuAssertIntEquals (test, 0, status);

	status = adapter.base.check_input_length (&adapter.base, in_len);
	CuAssertIntEquals (test, 0, status);

	acvp_proto_tester_adapter_release (&adapter);
}

static void acvp_proto_tester_dapter_test_check_input_length_too_small (CuTest *test)
{
	struct acvp_proto_tester_adapter adapter;
	int status;
	size_t in_len = 1;

	TEST_START;

	status = acvp_proto_tester_adapter_init (&adapter);
	CuAssertIntEquals (test, 0, status);

	status = adapter.base.check_input_length (&adapter.base, in_len);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_LENGTH_TOO_SMALL, status);

	status = adapter.base.check_input_length (&adapter.base, PB_BUF_WRITE_HEADER_SZ);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_LENGTH_TOO_SMALL, status);

	acvp_proto_tester_adapter_release (&adapter);
}

static void acvp_proto_tester_dapter_test_check_input_length_too_large (CuTest *test)
{
	struct acvp_proto_tester_adapter adapter;
	int status;
	size_t in_len = PB_BUF_WRITE_HEADER_SZ + ACVP_MAXDATA + 1;

	TEST_START;

	status = acvp_proto_tester_adapter_init (&adapter);
	CuAssertIntEquals (test, 0, status);

	status = adapter.base.check_input_length (&adapter.base, in_len);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_LENGTH_TOO_LARGE, status);

	acvp_proto_tester_adapter_release (&adapter);
}

static void acvp_proto_tester_dapter_test_check_input_length_null (CuTest *test)
{
	struct acvp_proto_tester_adapter adapter;
	int status;
	size_t in_len = 0x12345678;

	TEST_START;

	status = acvp_proto_tester_adapter_init (&adapter);
	CuAssertIntEquals (test, 0, status);

	status = adapter.base.check_input_length (NULL, in_len);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_INVALID_ARGUMENT, status);

	acvp_proto_tester_adapter_release (&adapter);
}

static void acvp_proto_tester_adapter_test_proto_test_algo_failure (CuTest *test)
{
	struct acvp_proto_tester_adapter adapter;
	int status;
	uint8_t *out = NULL;
	size_t out_length;

	TEST_START;

	status = acvp_proto_tester_adapter_init (&adapter);
	CuAssertIntEquals (test, 0, status);

	// Trigger failure by not registering any engines
	status = adapter.base.proto_test_algo (&adapter.base, ACVP_PROTO_TEST_DATA_SHA256,
		ACVP_PROTO_TEST_DATA_SHA256_LEN, &out, &out_length);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_TEST_FAILED, status);

	acvp_proto_tester_adapter_release (&adapter);
}

static void acvp_proto_tester_adapter_test_proto_test_algo_length_error (CuTest *test)
{
	struct acvp_proto_tester_adapter adapter;
	int status;
	uint8_t *out = NULL;
	size_t out_length;
	uint8_t in[1] = {0};

	TEST_START;

	status = acvp_proto_tester_adapter_init (&adapter);
	CuAssertIntEquals (test, 0, status);

	status = adapter.base.proto_test_algo (&adapter.base, in, sizeof (in), &out, &out_length);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_LENGTH_TOO_SMALL, status);
	CuAssertPtrEquals (test, NULL, out);

	status = adapter.base.proto_test_algo (&adapter.base, in, PB_BUF_WRITE_HEADER_SZ, &out,
		&out_length);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_LENGTH_TOO_SMALL, status);
	CuAssertPtrEquals (test, NULL, out);

	acvp_proto_tester_adapter_release (&adapter);
}

static void acvp_proto_tester_adapter_test_proto_test_algo_null (CuTest *test)
{
	struct acvp_proto_tester_adapter adapter;
	int status;
	uint8_t *out = NULL;
	size_t out_length;
	uint8_t in[1] = {0};

	TEST_START;

	status = acvp_proto_tester_adapter_init (&adapter);
	CuAssertIntEquals (test, 0, status);

	status = adapter.base.proto_test_algo (NULL, in, 0, &out, &out_length);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, out);

	status = adapter.base.proto_test_algo (&adapter.base, NULL, 0, &out, &out_length);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, out);

	status = adapter.base.proto_test_algo (&adapter.base, in, 0, NULL, &out_length);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, out);

	status = adapter.base.proto_test_algo (&adapter.base, in, 0, &out, NULL);
	CuAssertIntEquals (test, ACVP_PROTO_TESTER_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, out);

	acvp_proto_tester_adapter_release (&adapter);
}

// *INDENT-OFF*
TEST_SUITE_START (acvp_proto_tester_adapter);

TEST (acvp_proto_tester_adapter_test_init);
TEST (acvp_proto_tester_adapter_test_init_null);
TEST (acvp_proto_tester_dapter_test_check_input_length);
TEST (acvp_proto_tester_dapter_test_check_input_length_too_small);
TEST (acvp_proto_tester_dapter_test_check_input_length_too_large);
TEST (acvp_proto_tester_dapter_test_check_input_length_null);
// NOTE: This test is excluded because of the Acvpparser library callback registration dependency.
// TEST (acvp_proto_tester_adapter_test_proto_test_algo);
TEST (acvp_proto_tester_adapter_test_proto_test_algo_failure);
TEST (acvp_proto_tester_adapter_test_proto_test_algo_length_error);
TEST (acvp_proto_tester_adapter_test_proto_test_algo_null);

TEST_SUITE_END;
// *INDENT-ON*
