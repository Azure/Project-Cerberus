// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "crypto/aes_key_wrap.h"
#include "crypto/aes_key_wrap_static.h"
#include "testing/engines/aes_testing_engine.h"
#include "testing/mock/crypto/aes_ecb_mock.h"


TEST_SUITE_LABEL ("aes_key_wrap");


/**
 * Test key for AES-256 wrapping from RFC 3394 test vectors.
 */
const uint8_t AES_KEY_WRAP_TESTING_KEY[] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

const size_t AES_KEY_WRAP_TESTING_KEY_LEN = sizeof (AES_KEY_WRAP_TESTING_KEY);

/**
 * 128-bit test data for AES-256 wrapping from RFC 3394 test vectors.
 */
const uint8_t AES_KEY_WRAP_TESTING_128BIT_DATA[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

const size_t AES_KEY_WRAP_TESTING_128BIT_DATA_LEN = sizeof (AES_KEY_WRAP_TESTING_128BIT_DATA);

/**
 * Wrapped 128-bit test data with AES-256 from RFC 3394 test vectors.
 */
const uint8_t AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED[] = {
	0x64, 0xe8, 0xc3, 0xf9, 0xce, 0x0f, 0x5b, 0xa2, 0x63, 0xe9, 0x77, 0x79, 0x05, 0x81, 0x8a, 0x2a,
	0x93, 0xc8, 0x19, 0x1e, 0x7d, 0x6e, 0x8a, 0xe7
};

const size_t AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN =
	sizeof (AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED);

/**
 * 192-bit test data for AES-256 wrapping from RFC 3394 test vectors.
 */
const uint8_t AES_KEY_WRAP_TESTING_192BIT_DATA[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};

const size_t AES_KEY_WRAP_TESTING_192BIT_DATA_LEN = sizeof (AES_KEY_WRAP_TESTING_192BIT_DATA);

/**
 * Wrapped 192-bit test data with AES-256 from RFC 3394 test vectors.
 */
const uint8_t AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED[] = {
	0xa8, 0xf9, 0xbc, 0x16, 0x12, 0xc6, 0x8b, 0x3f, 0xf6, 0xe6, 0xf4, 0xfb, 0xe3, 0x0e, 0x71, 0xe4,
	0x76, 0x9c, 0x8b, 0x80, 0xa3, 0x2c, 0xb8, 0x95, 0x8c, 0xd5, 0xd1, 0x7d, 0x6b, 0x25, 0x4d, 0xa1
};

const size_t AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED_LEN =
	sizeof (AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED);

/**
 * 256-bit test data for AES-256 wrapping from RFC 3394 test vectors.
 */
const uint8_t AES_KEY_WRAP_TESTING_256BIT_DATA[] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

const size_t AES_KEY_WRAP_TESTING_256BIT_DATA_LEN = sizeof (AES_KEY_WRAP_TESTING_256BIT_DATA);

/**
 * Wrapped 256-bit test data with AES-256 from RFC 3394 test vectors.
 */
const uint8_t AES_KEY_WRAP_TESTING_256BIT_DATA_WRAPPED[] = {
	0x28, 0xc9, 0xf4, 0x04, 0xc4, 0xb8, 0x10, 0xf4, 0xcb, 0xcc, 0xb3, 0x5c, 0xfb, 0x87, 0xf8, 0x26,
	0x3f, 0x57, 0x86, 0xe2, 0xd8, 0x0e, 0xd3, 0x26, 0xcb, 0xc7, 0xf0, 0xe7, 0x1a, 0x99, 0xf4, 0x3b,
	0xfb, 0x98, 0x8b, 0x9b, 0x7a, 0x02, 0xdd, 0x21
};

const size_t AES_KEY_WRAP_TESTING_256BIT_DATA_WRAPPED_LEN =
	sizeof (AES_KEY_WRAP_TESTING_256BIT_DATA_WRAPPED);


/**
 * Dependencies for testing AES key wrap.
 */
struct aes_key_wrap_testing {
	AES_ECB_TESTING_ENGINE (ecb);			/**< AES-ECB engine to use for testing. */
	struct aes_ecb_engine_mock ecb_mock;	/**< Mock for AES-ECB operations. */
	struct aes_key_wrap test;				/**< AES key wrapping under test. */
};


/**
 * Initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param aes_kw Testing dependencies to initialize.
 */
static void aes_key_wrap_testing_init_dependencies (CuTest *test,
	struct aes_key_wrap_testing *aes_kw)
{
	int status;

	status = AES_ECB_TESTING_ENGINE_INIT (&aes_kw->ecb);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_mock_init (&aes_kw->ecb_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release all testing dependencies and validate mocks.
 *
 * @param test The test framework.
 * @param aes_kw Testing dependencies to release.
 */
static void aes_key_wrap_testing_release_dependencies (CuTest *test,
	struct aes_key_wrap_testing *aes_kw)
{
	int status;

	status = aes_ecb_mock_validate_and_release (&aes_kw->ecb_mock);
	CuAssertIntEquals (test, 0, status);

	AES_ECB_TESTING_ENGINE_RELEASE (&aes_kw->ecb);
}

/**
 * Initialize AES key wrap for testing.
 *
 * @param test The test framework.
 * @param aes_kw Testing components to initialize.
 */
static void aes_key_wrap_testing_init (CuTest *test, struct aes_key_wrap_testing *aes_kw)
{
	int status;

	aes_key_wrap_testing_init_dependencies (test, aes_kw);

	status = aes_key_wrap_init (&aes_kw->test, &aes_kw->ecb.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize AES key wrap for testing using a mock for AES-ECB operations.
 *
 * @param test The test framework.
 * @param aes_kw Testing components to initialize.
 */
static void aes_key_wrap_testing_init_with_mock (CuTest *test, struct aes_key_wrap_testing *aes_kw)
{
	int status;

	aes_key_wrap_testing_init_dependencies (test, aes_kw);

	status = aes_key_wrap_init (&aes_kw->test, &aes_kw->ecb_mock.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param aes_kw Testing components to release.
 */
static void aes_key_wrap_testing_release (CuTest *test, struct aes_key_wrap_testing *aes_kw)
{
	aes_key_wrap_testing_release_dependencies (test, aes_kw);

	aes_key_wrap_release (&aes_kw->test);
}


/*******************
 * Test cases
 *******************/

static void aes_key_wrap_test_init (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;

	TEST_START;

	aes_key_wrap_testing_init_dependencies (test, &aes_kw);

	status = aes_key_wrap_init (&aes_kw.test, &aes_kw.ecb.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, aes_kw.test.base.set_kek);
	CuAssertPtrNotNull (test, aes_kw.test.base.clear_kek);
	CuAssertPtrNotNull (test, aes_kw.test.base.wrap);
	CuAssertPtrNotNull (test, aes_kw.test.base.unwrap);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_init_null (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;

	TEST_START;

	aes_key_wrap_testing_init_dependencies (test, &aes_kw);

	status = aes_key_wrap_init (NULL, &aes_kw.ecb.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_key_wrap_init (&aes_kw.test, NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_testing_release_dependencies (test, &aes_kw);
}

static void aes_key_wrap_test_static_init (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw = {
		.test = aes_key_wrap_static_init (&aes_kw.ecb.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, aes_kw.test.base.set_kek);
	CuAssertPtrNotNull (test, aes_kw.test.base.clear_kek);
	CuAssertPtrNotNull (test, aes_kw.test.base.wrap);
	CuAssertPtrNotNull (test, aes_kw.test.base.unwrap);

	aes_key_wrap_testing_init_dependencies (test, &aes_kw);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_release_null (CuTest *test)
{
	TEST_START;

	aes_key_wrap_release (NULL);
}

static void aes_key_wrap_test_set_kek (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;

	TEST_START;

	aes_key_wrap_testing_init_with_mock (test, &aes_kw);

	status = mock_expect (&aes_kw.ecb_mock.mock, aes_kw.ecb_mock.base.set_key, &aes_kw.ecb_mock, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_TESTING_KEY, AES_KEY_WRAP_TESTING_KEY_LEN),
		MOCK_ARG (AES_KEY_WRAP_TESTING_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_set_kek_static_init (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw = {
		.test = aes_key_wrap_static_init (&aes_kw.ecb_mock.base)
	};
	int status;

	TEST_START;

	aes_key_wrap_testing_init_dependencies (test, &aes_kw);

	status = mock_expect (&aes_kw.ecb_mock.mock, aes_kw.ecb_mock.base.set_key, &aes_kw.ecb_mock, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_TESTING_KEY, AES_KEY_WRAP_TESTING_KEY_LEN),
		MOCK_ARG (AES_KEY_WRAP_TESTING_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_set_kek_null (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;

	TEST_START;

	aes_key_wrap_testing_init_with_mock (test, &aes_kw);

	status = aes_kw.test.base.set_kek (NULL, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_set_kek_error (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;

	TEST_START;

	aes_key_wrap_testing_init_with_mock (test, &aes_kw);

	status = mock_expect (&aes_kw.ecb_mock.mock, aes_kw.ecb_mock.base.set_key, &aes_kw.ecb_mock,
		AES_ECB_ENGINE_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_TESTING_KEY, AES_KEY_WRAP_TESTING_KEY_LEN),
		MOCK_ARG (AES_KEY_WRAP_TESTING_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, AES_ECB_ENGINE_SET_KEY_FAILED, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_clear_kek (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;

	TEST_START;

	aes_key_wrap_testing_init_with_mock (test, &aes_kw);

	status = mock_expect (&aes_kw.ecb_mock.mock, aes_kw.ecb_mock.base.clear_key, &aes_kw.ecb_mock,
		0);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.clear_kek (&aes_kw.test.base);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_clear_kek_static_init (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw = {
		.test = aes_key_wrap_static_init (&aes_kw.ecb_mock.base)
	};
	int status;

	TEST_START;

	aes_key_wrap_testing_init_dependencies (test, &aes_kw);

	status = mock_expect (&aes_kw.ecb_mock.mock, aes_kw.ecb_mock.base.clear_key, &aes_kw.ecb_mock,
		0);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.clear_kek (&aes_kw.test.base);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_clear_kek_null (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;

	TEST_START;

	aes_key_wrap_testing_init_with_mock (test, &aes_kw);

	status = aes_kw.test.base.clear_kek (NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_clear_kek_error (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;

	TEST_START;

	aes_key_wrap_testing_init_with_mock (test, &aes_kw);

	status = mock_expect (&aes_kw.ecb_mock.mock, aes_kw.ecb_mock.base.clear_key, &aes_kw.ecb_mock,
		AES_ECB_ENGINE_CLEAR_KEY_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.clear_kek (&aes_kw.test.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_CLEAR_KEY_FAILED, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_128bit (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, sizeof (wrapped));

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA,
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_192bit (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_192BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED_LEN, sizeof (wrapped));

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_192BIT_DATA,
		AES_KEY_WRAP_TESTING_192BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_256bit (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_256BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_256BIT_DATA_WRAPPED_LEN, sizeof (wrapped));

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_256BIT_DATA,
		AES_KEY_WRAP_TESTING_256BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_256BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_same_buffer_wrapped_offset_from_data (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];

	TEST_START;

	memcpy (&wrapped[8], AES_KEY_WRAP_TESTING_128BIT_DATA, AES_KEY_WRAP_TESTING_128BIT_DATA_LEN);

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, &wrapped[8],
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_same_buffer_wrapped_same_as_data (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];

	TEST_START;

	memcpy (wrapped, AES_KEY_WRAP_TESTING_128BIT_DATA, AES_KEY_WRAP_TESTING_128BIT_DATA_LEN);

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, wrapped,
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_static_init (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw = {
		.test = aes_key_wrap_static_init (&aes_kw.ecb.base)
	};
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];

	TEST_START;

	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, sizeof (wrapped));

	aes_key_wrap_testing_init_dependencies (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA,
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED, wrapped,
		sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_null (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (NULL, AES_KEY_WRAP_TESTING_128BIT_DATA,
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, NULL, AES_KEY_WRAP_TESTING_128BIT_DATA_LEN,
		wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA,
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, NULL, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_not_64bit_aligned (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_192BIT_DATA_LEN)];

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_192BIT_DATA,
		AES_KEY_WRAP_TESTING_192BIT_DATA_LEN - 1, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_NOT_BLOCK_ALIGNED, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_data_too_short (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA,
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN - 8, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_KEY_WRAP_NOT_ENOUGH_DATA, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_wrapped_buffer_too_small (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA,
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, wrapped, sizeof (wrapped) - 1);
	CuAssertIntEquals (test, AES_KEY_WRAP_SMALL_OUTPUT_BUFFER, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_wrap_ecb_error (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];
	uint8_t zero[sizeof (wrapped)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.wrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA,
		AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	status = testing_validate_array (zero, wrapped, sizeof (wrapped));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_128bit (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_128BIT_DATA_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_128BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_192bit (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_192BIT_DATA_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_192BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_192BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_256bit (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_256BIT_DATA_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_256BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_256BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_256BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_256BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_same_buffer_data_offset_from_wrapped (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];
	size_t length = AES_KEY_WRAP_TESTING_128BIT_DATA_LEN;

	TEST_START;

	memcpy (data, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN);

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, data, sizeof (data), &data[8], &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_128BIT_DATA, &data[8], length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_same_buffer_data_same_as_wrapped (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];
	size_t length = sizeof (data);

	TEST_START;

	memcpy (data, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN);

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, data, sizeof (data), data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_128BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_static_init (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw = {
		.test = aes_key_wrap_static_init (&aes_kw.ecb.base)
	};
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_128BIT_DATA_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_testing_init_dependencies (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, AES_KEY_WRAP_TESTING_128BIT_DATA_LEN, length);

	status = testing_validate_array (AES_KEY_WRAP_TESTING_128BIT_DATA, data, length);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_null (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_128BIT_DATA_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (NULL, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, NULL,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, NULL, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, data, NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_not_64bit_aligned (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_192BIT_DATA_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_192BIT_DATA_WRAPPED_LEN - 1, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_NOT_BLOCK_ALIGNED, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_data_too_short (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_128BIT_DATA_LEN];
	size_t length = sizeof (data);

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN - 8, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_NOT_ENOUGH_DATA, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_data_buffer_too_small (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_128BIT_DATA_LEN];
	size_t length = sizeof (data) - 1;

	TEST_START;

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_SMALL_OUTPUT_BUFFER, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_corrupt_wrapped_data (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];
	uint8_t data[AES_KEY_WRAP_TESTING_128BIT_DATA_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	memcpy (wrapped, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN);
	wrapped[10] ^= 0x55;	/* Corrupt the data region of the wrapped buffer. */

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, wrapped, sizeof (wrapped), data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTEGRITY_CHECK_FAIL, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_corrupt_integrity_check (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t wrapped[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (AES_KEY_WRAP_TESTING_128BIT_DATA_LEN)];
	uint8_t data[AES_KEY_WRAP_TESTING_128BIT_DATA_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	memcpy (wrapped, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN);
	wrapped[2] ^= 0x55;	/* Corrupt the integrity check region of the wrapped buffer. */

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.set_kek (&aes_kw.test.base, AES_KEY_WRAP_TESTING_KEY,
		AES_KEY_WRAP_TESTING_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, wrapped, sizeof (wrapped), data, &length);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTEGRITY_CHECK_FAIL, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}

static void aes_key_wrap_test_unwrap_ecb_error (CuTest *test)
{
	struct aes_key_wrap_testing aes_kw;
	int status;
	uint8_t data[AES_KEY_WRAP_TESTING_128BIT_DATA_LEN];
	size_t length = sizeof (data);
	uint8_t zero[sizeof (data)];

	TEST_START;

	memset (zero, 0, sizeof (zero));

	aes_key_wrap_testing_init (test, &aes_kw);

	status = aes_kw.test.base.unwrap (&aes_kw.test.base, AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED,
		AES_KEY_WRAP_TESTING_128BIT_DATA_WRAPPED_LEN, data, &length);
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	status = testing_validate_array (zero, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_testing_release (test, &aes_kw);
}


// *INDENT-OFF*
TEST_SUITE_START (aes_key_wrap);

TEST (aes_key_wrap_test_init);
TEST (aes_key_wrap_test_init_null);
TEST (aes_key_wrap_test_static_init);
TEST (aes_key_wrap_test_release_null);
TEST (aes_key_wrap_test_set_kek);
TEST (aes_key_wrap_test_set_kek_static_init);
TEST (aes_key_wrap_test_set_kek_null);
TEST (aes_key_wrap_test_set_kek_error);
TEST (aes_key_wrap_test_clear_kek);
TEST (aes_key_wrap_test_clear_kek_static_init);
TEST (aes_key_wrap_test_clear_kek_null);
TEST (aes_key_wrap_test_clear_kek_error);
TEST (aes_key_wrap_test_wrap_128bit);
TEST (aes_key_wrap_test_wrap_192bit);
TEST (aes_key_wrap_test_wrap_256bit);
TEST (aes_key_wrap_test_wrap_same_buffer_wrapped_offset_from_data);
TEST (aes_key_wrap_test_wrap_same_buffer_wrapped_same_as_data);
TEST (aes_key_wrap_test_wrap_static_init);
TEST (aes_key_wrap_test_wrap_null);
TEST (aes_key_wrap_test_wrap_not_64bit_aligned);
TEST (aes_key_wrap_test_wrap_data_too_short);
TEST (aes_key_wrap_test_wrap_wrapped_buffer_too_small);
TEST (aes_key_wrap_test_wrap_ecb_error);
TEST (aes_key_wrap_test_unwrap_128bit);
TEST (aes_key_wrap_test_unwrap_192bit);
TEST (aes_key_wrap_test_unwrap_256bit);
TEST (aes_key_wrap_test_unwrap_same_buffer_data_offset_from_wrapped);
TEST (aes_key_wrap_test_unwrap_same_buffer_data_same_as_wrapped);
TEST (aes_key_wrap_test_unwrap_static_init);
TEST (aes_key_wrap_test_unwrap_null);
TEST (aes_key_wrap_test_unwrap_not_64bit_aligned);
TEST (aes_key_wrap_test_unwrap_data_too_short);
TEST (aes_key_wrap_test_unwrap_data_buffer_too_small);
TEST (aes_key_wrap_test_unwrap_corrupt_wrapped_data);
TEST (aes_key_wrap_test_unwrap_corrupt_integrity_check);
TEST (aes_key_wrap_test_unwrap_ecb_error);

TEST_SUITE_END;
// *INDENT-ON*
