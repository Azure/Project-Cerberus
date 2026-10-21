// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/kat/hash_kat.h"
#include "crypto/kat/hash_kat_vectors.h"
#include "crypto/kat/hmac_kat_vectors.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"


TEST_SUITE_LABEL ("hash_kat");


/**
 * SHA1 hash of HMAC_KAT_VECTORS_CALCULATE_KEY.
 */
const uint8_t SHA1_HMAC_KAT_CALCULATE_KEY_HASH[] = {
	0xbc, 0xa3, 0x89, 0xa0, 0xdf, 0x8a, 0xde, 0x31, 0x1c, 0xc4, 0xd4, 0xd6, 0x04, 0x7b, 0xe8, 0xaf,
	0xfe, 0xd7, 0x78, 0xb9
};

/**
 * SHA256 hash of HMAC_KAT_VECTORS_CALCULATE_KEY.
 */
const uint8_t SHA256_HMAC_KAT_CALCULATE_KEY_HASH[] = {
	0x4c, 0x12, 0x90, 0x69, 0x31, 0x9f, 0xf5, 0x30, 0x9f, 0x36, 0xf8, 0xed, 0x31, 0x8e, 0x86, 0xf0,
	0x76, 0x8e, 0xdb, 0xe2, 0x95, 0x6d, 0xf7, 0x69, 0x35, 0x08, 0x81, 0xb6, 0x1a, 0xf7, 0xf0, 0x94
};

/**
 * SHA384 hash of HMAC_KAT_VECTORS_CALCULATE_KEY.
 */
const uint8_t SHA384_HMAC_KAT_CALCULATE_KEY_HASH[] = {
	0x75, 0xee, 0xe9, 0xaf, 0x74, 0x5c, 0x63, 0xbf, 0x11, 0x25, 0xfd, 0x79, 0x59, 0xad, 0x9c, 0x31,
	0x3f, 0x33, 0x45, 0x4b, 0xd8, 0xe2, 0xe3, 0x3d, 0xc7, 0xa8, 0xe9, 0x6b, 0xc1, 0xd0, 0x30, 0x7b,
	0x68, 0x8d, 0xc5, 0x73, 0x8f, 0x62, 0xb9, 0xbd, 0x84, 0x24, 0xcf, 0xd0, 0xca, 0x35, 0x57, 0x70
};

/**
 * SHA512 hash of HMAC_KAT_VECTORS_CALCULATE_KEY.
 */
const uint8_t SHA512_HMAC_KAT_CALCULATE_KEY_HASH[] = {
	0xc7, 0xbb, 0x62, 0x07, 0xde, 0xd7, 0x35, 0x46, 0x43, 0x81, 0xc5, 0xab, 0x93, 0x06, 0xc3, 0x0e,
	0xb4, 0x29, 0x79, 0x9f, 0x96, 0x81, 0x82, 0xdb, 0xb7, 0xa9, 0x74, 0xa0, 0xdc, 0xad, 0x29, 0xcc,
	0x22, 0x8b, 0x47, 0xf6, 0x20, 0x39, 0xc3, 0xbb, 0x17, 0x69, 0x69, 0x1a, 0x02, 0xf3, 0xa1, 0x04,
	0xdb, 0x7b, 0xc4, 0x80, 0x4f, 0xbe, 0x73, 0x9f, 0x92, 0xad, 0xb7, 0xb8, 0xc9, 0xdd, 0x0e, 0xc1
};


/*******************
 * Test cases
 *******************/

static void hash_kat_test_run_self_test_calculate_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha1 (&engine.base);
#ifdef HASH_ENABLE_SHA1
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA1
static void hash_kat_test_run_self_test_calculate_sha1_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA1_TEST_HASH, SHA1_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_calculate_sha1_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha1 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_calculate_sha1_calculate_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine,
		HASH_ENGINE_SHA1_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_self_test_calculate_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_calculate_sha256_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha256, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_calculate_sha256_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha256 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_calculate_sha256_calculate_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha256, &engine,
		HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_calculate_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha384 (&engine.base);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA384
static void hash_kat_test_run_self_test_calculate_sha384_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha384, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA384_TEST_HASH, SHA384_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA384_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_calculate_sha384_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha384 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_calculate_sha384_calculate_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha384, &engine,
		HASH_ENGINE_SHA384_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_self_test_calculate_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha512 (&engine.base);
#ifdef HASH_ENABLE_SHA512
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA512
static void hash_kat_test_run_self_test_calculate_sha512_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha512, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA512_TEST_HASH, SHA512_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA512_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_calculate_sha512_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha512 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_calculate_sha512_calculate_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha512, &engine,
		HASH_ENGINE_SHA512_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_calculate_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_all_calculate_self_tests (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_calculate_self_tests (&engine.base);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_all_calculate_self_tests_mock (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA1_DIGEST,
		SHA1_HASH_LENGTH, 3);
#endif

	status |= mock_expect (&engine.mock, engine.base.calculate_sha256, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA256_DIGEST,
		SHA256_HASH_LENGTH, 3);

#ifdef HASH_ENABLE_SHA384
	status |= mock_expect (&engine.mock, engine.base.calculate_sha384, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA384_DIGEST,
		SHA384_HASH_LENGTH, 3);
#endif

#ifdef HASH_ENABLE_SHA512
	status |= mock_expect (&engine.mock, engine.base.calculate_sha512, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA512_DIGEST,
		SHA512_HASH_LENGTH, 3);
#endif

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_calculate_self_tests (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_all_calculate_self_tests_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_calculate_self_tests (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA1
static void hash_kat_test_run_all_calculate_self_tests_sha1_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine,
		HASH_ENGINE_SHA1_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_calculate_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_all_calculate_self_tests_sha256_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA1_DIGEST,
		SHA1_HASH_LENGTH, 3);
#endif

	status |= mock_expect (&engine.mock, engine.base.calculate_sha256, &engine,
		HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_calculate_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

#ifdef HASH_ENABLE_SHA384
static void hash_kat_test_run_all_calculate_self_tests_sha384_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA1_DIGEST,
		SHA1_HASH_LENGTH, 3);
#endif

	status |= mock_expect (&engine.mock, engine.base.calculate_sha256, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA256_DIGEST,
		SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&engine.mock, engine.base.calculate_sha384, &engine,
		HASH_ENGINE_SHA384_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_calculate_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void hash_kat_test_run_all_calculate_self_tests_sha512_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA1_DIGEST,
		SHA1_HASH_LENGTH, 3);
#endif

	status |= mock_expect (&engine.mock, engine.base.calculate_sha256, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA256_DIGEST,
		SHA256_HASH_LENGTH, 3);

#ifdef HASH_ENABLE_SHA384
	status |= mock_expect (&engine.mock, engine.base.calculate_sha384, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 2, SHA_KAT_VECTORS_CALCULATE_SHA384_DIGEST,
		SHA384_HASH_LENGTH, 3);
#endif

	status |= mock_expect (&engine.mock, engine.base.calculate_sha512, &engine,
		HASH_ENGINE_SHA512_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_CALCULATE_DATA, SHA_KAT_VECTORS_CALCULATE_DATA_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_CALCULATE_DATA_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_calculate_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_self_test_update_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha1 (&engine.base);
#ifdef HASH_ENABLE_SHA1
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA1
static void hash_kat_test_run_self_test_update_sha1_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA1_TEST2_HASH, SHA1_HASH_LENGTH, 1);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha1_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha1 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_update_sha1_start_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine,
		HASH_ENGINE_START_SHA1_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha1_update_first_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha1_update_second_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha1_finish_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_self_test_update_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_update_sha256_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA256_TEST2_HASH, SHA256_HASH_LENGTH, 1);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha256_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha256 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_update_sha256_start_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha256_update_first_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha256_update_second_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha256_finish_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha384 (&engine.base);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA384
static void hash_kat_test_run_self_test_update_sha384_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha384, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA384_TEST2_HASH, SHA384_HASH_LENGTH, 1);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA384_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha384_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha384 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_update_sha384_start_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha384, &engine,
		HASH_ENGINE_START_SHA384_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha384_update_first_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha384, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha384_update_second_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha384, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha384_finish_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha384, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_self_test_update_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha512 (&engine.base);
#ifdef HASH_ENABLE_SHA512
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA512
static void hash_kat_test_run_self_test_update_sha512_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha512, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA512_TEST2_HASH, SHA512_HASH_LENGTH, 1);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA512_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha512_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha512 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_self_test_update_sha512_start_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha512, &engine,
		HASH_ENGINE_START_SHA512_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha512_update_first_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha512, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha512_update_second_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha512, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_self_test_update_sha512_finish_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha512, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_self_test_update_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_all_update_self_tests (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_update_self_tests (&engine.base);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_run_all_update_self_tests_mock (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA1_DIGEST,
		SHA1_HASH_LENGTH, 1);
#endif

	status |= mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA256_DIGEST,
		SHA256_HASH_LENGTH, 1);

#ifdef HASH_ENABLE_SHA384
	status |= mock_expect (&engine.mock, engine.base.start_sha384, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA384_DIGEST,
		SHA384_HASH_LENGTH, 1);
#endif

#ifdef HASH_ENABLE_SHA512
	status |= mock_expect (&engine.mock, engine.base.start_sha512, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA512_DIGEST,
		SHA512_HASH_LENGTH, 1);
#endif

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_update_self_tests (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_run_all_update_self_tests_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_update_self_tests (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA1
static void hash_kat_test_run_all_update_self_tests_sha1_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine,
		HASH_ENGINE_START_SHA1_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_update_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_run_all_update_self_tests_sha256_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA1_DIGEST,
		SHA1_HASH_LENGTH, 1);
#endif

	status |= mock_expect (&engine.mock, engine.base.start_sha256, &engine,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_update_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

#ifdef HASH_ENABLE_SHA384
static void hash_kat_test_run_all_update_self_tests_sha384_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA1_DIGEST,
		SHA1_HASH_LENGTH, 1);
#endif

	status |= mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA256_DIGEST,
		SHA256_HASH_LENGTH, 1);

	status |= mock_expect (&engine.mock, engine.base.start_sha384, &engine,
		HASH_ENGINE_START_SHA384_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_update_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void hash_kat_test_run_all_update_self_tests_sha512_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA1_DIGEST,
		SHA1_HASH_LENGTH, 1);
#endif

	status |= mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA256_DIGEST,
		SHA256_HASH_LENGTH, 1);

#ifdef HASH_ENABLE_SHA384
	status |= mock_expect (&engine.mock, engine.base.start_sha384, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_1, SHA_KAT_VECTORS_UPDATE_DATA_1_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_1_LEN));
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0,
		MOCK_ARG_PTR_CONTAINS (SHA_KAT_VECTORS_UPDATE_DATA_2, SHA_KAT_VECTORS_UPDATE_DATA_2_LEN),
		MOCK_ARG (SHA_KAT_VECTORS_UPDATE_DATA_2_LEN));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	status |= mock_expect_output (&engine.mock, 0, SHA_KAT_VECTORS_UPDATE_SHA384_DIGEST,
		SHA384_HASH_LENGTH, 1);
#endif

	status |= mock_expect (&engine.mock, engine.base.start_sha512, &engine,
		HASH_ENGINE_START_SHA512_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_run_all_update_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_hmac_run_self_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha1 (&engine.base);
#ifdef HASH_ENABLE_SHA1
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA1
static void hash_kat_test_hmac_run_self_test_sha1_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA1_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA1, SHA1_TEST_HMAC, SHA1_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_HMAC_SHA1_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_hmac_run_self_test_sha1_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha1 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_hmac_run_self_test_sha1_calculate_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine,
		HASH_ENGINE_SHA1_FAILED,
		MOCK_ARG_PTR_CONTAINS (HMAC_KAT_VECTORS_CALCULATE_KEY, HMAC_KAT_VECTORS_CALCULATE_KEY_LEN),
		MOCK_ARG (HMAC_KAT_VECTORS_CALCULATE_KEY_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_hmac_run_self_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_hmac_run_self_test_sha256_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA256_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA256, SHA256_TEST_HMAC, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_HMAC_SHA256_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_hmac_run_self_test_sha256_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha256 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_hmac_run_self_test_sha256_calculate_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha256, &engine,
		HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (HMAC_KAT_VECTORS_CALCULATE_KEY, HMAC_KAT_VECTORS_CALCULATE_KEY_LEN),
		MOCK_ARG (HMAC_KAT_VECTORS_CALCULATE_KEY_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_hmac_run_self_test_sha384 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha384 (&engine.base);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA384
static void hash_kat_test_hmac_run_self_test_sha384_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA384_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA384, SHA384_TEST_HMAC, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_HMAC_SHA384_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_hmac_run_self_test_sha384_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha384 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_hmac_run_self_test_sha384_calculate_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha384, &engine,
		HASH_ENGINE_SHA384_FAILED,
		MOCK_ARG_PTR_CONTAINS (HMAC_KAT_VECTORS_CALCULATE_KEY, HMAC_KAT_VECTORS_CALCULATE_KEY_LEN),
		MOCK_ARG (HMAC_KAT_VECTORS_CALCULATE_KEY_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_hmac_run_self_test_sha512 (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha512 (&engine.base);
#ifdef HASH_ENABLE_SHA512
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA512
static void hash_kat_test_hmac_run_self_test_sha512_mismatch_data (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA512_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA512, SHA512_TEST_HMAC, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_HMAC_SHA512_SELF_TEST_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_hmac_run_self_test_sha512_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha512 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_hmac_run_self_test_sha512_calculate_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha512, &engine,
		HASH_ENGINE_SHA512_FAILED,
		MOCK_ARG_PTR_CONTAINS (HMAC_KAT_VECTORS_CALCULATE_KEY, HMAC_KAT_VECTORS_CALCULATE_KEY_LEN),
		MOCK_ARG (HMAC_KAT_VECTORS_CALCULATE_KEY_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_self_test_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_hmac_run_all_self_tests (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_all_self_tests (&engine.base);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_kat_test_hmac_run_all_self_tests_mock (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA1_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA1, HMAC_KAT_VECTORS_CALCULATE_SHA1_MAC, SHA1_HASH_LENGTH);
#endif

	status |= hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA256_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA256, HMAC_KAT_VECTORS_CALCULATE_SHA256_MAC, SHA256_HASH_LENGTH);

#ifdef HASH_ENABLE_SHA384
	status |= hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA384_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA384, HMAC_KAT_VECTORS_CALCULATE_SHA384_MAC, SHA384_HASH_LENGTH);
#endif

#ifdef HASH_ENABLE_SHA512
	status |= hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA512_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA512, HMAC_KAT_VECTORS_CALCULATE_SHA512_MAC, SHA512_HASH_LENGTH);
#endif

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_all_self_tests (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_kat_test_hmac_run_all_self_tests_null (CuTest *test)
{
	HASH_TESTING_ENGINE (engine);
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_all_self_tests (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

#ifdef HASH_ENABLE_SHA1
static void hash_kat_test_hmac_run_all_self_tests_sha1_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine,
		HASH_ENGINE_SHA1_FAILED,
		MOCK_ARG_PTR_CONTAINS (HMAC_KAT_VECTORS_CALCULATE_KEY, HMAC_KAT_VECTORS_CALCULATE_KEY_LEN),
		MOCK_ARG (HMAC_KAT_VECTORS_CALCULATE_KEY_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA1_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_all_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void hash_kat_test_hmac_run_all_self_tests_sha256_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA1_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA1, HMAC_KAT_VECTORS_CALCULATE_SHA1_MAC, SHA1_HASH_LENGTH);
#endif

	status = mock_expect (&engine.mock, engine.base.calculate_sha256, &engine,
		HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_PTR_CONTAINS (HMAC_KAT_VECTORS_CALCULATE_KEY, HMAC_KAT_VECTORS_CALCULATE_KEY_LEN),
		MOCK_ARG (HMAC_KAT_VECTORS_CALCULATE_KEY_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_all_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

#ifdef HASH_ENABLE_SHA384
static void hash_kat_test_hmac_run_all_self_tests_sha384_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA1_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA1, HMAC_KAT_VECTORS_CALCULATE_SHA1_MAC, SHA1_HASH_LENGTH);
#endif

	status |= hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA256_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA256, HMAC_KAT_VECTORS_CALCULATE_SHA256_MAC, SHA256_HASH_LENGTH);

	status = mock_expect (&engine.mock, engine.base.calculate_sha384, &engine,
		HASH_ENGINE_SHA384_FAILED,
		MOCK_ARG_PTR_CONTAINS (HMAC_KAT_VECTORS_CALCULATE_KEY, HMAC_KAT_VECTORS_CALCULATE_KEY_LEN),
		MOCK_ARG (HMAC_KAT_VECTORS_CALCULATE_KEY_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA384_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_all_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void hash_kat_test_hmac_run_all_self_tests_sha512_fail (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

#ifdef HASH_ENABLE_SHA1
	status = hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA1_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA1, HMAC_KAT_VECTORS_CALCULATE_SHA1_MAC, SHA1_HASH_LENGTH);
#endif

	status |= hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA256_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA256, HMAC_KAT_VECTORS_CALCULATE_SHA256_MAC, SHA256_HASH_LENGTH);

#ifdef HASH_ENABLE_SHA384
	status |= hash_mock_expect_hmac_large_key (&engine, HMAC_KAT_VECTORS_CALCULATE_KEY,
		HMAC_KAT_VECTORS_CALCULATE_KEY_LEN, SHA384_HMAC_KAT_CALCULATE_KEY_HASH,
		HMAC_KAT_VECTORS_CALCULATE_DATA, HMAC_KAT_VECTORS_CALCULATE_DATA_LEN, NULL, 0,
		HASH_TYPE_SHA384, HMAC_KAT_VECTORS_CALCULATE_SHA384_MAC, SHA384_HASH_LENGTH);
#endif

	status = mock_expect (&engine.mock, engine.base.calculate_sha512, &engine,
		HASH_ENGINE_SHA512_FAILED,
		MOCK_ARG_PTR_CONTAINS (HMAC_KAT_VECTORS_CALCULATE_KEY, HMAC_KAT_VECTORS_CALCULATE_KEY_LEN),
		MOCK_ARG (HMAC_KAT_VECTORS_CALCULATE_KEY_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA512_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = hash_kat_hmac_run_all_self_tests (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}
#endif


// *INDENT-OFF*
TEST_SUITE_START (hash_kat);

TEST (hash_kat_test_run_self_test_calculate_sha1);
#ifdef HASH_ENABLE_SHA1
TEST (hash_kat_test_run_self_test_calculate_sha1_mismatch_data);
TEST (hash_kat_test_run_self_test_calculate_sha1_null);
TEST (hash_kat_test_run_self_test_calculate_sha1_calculate_fail);
#endif
TEST (hash_kat_test_run_self_test_calculate_sha256);
TEST (hash_kat_test_run_self_test_calculate_sha256_mismatch_data);
TEST (hash_kat_test_run_self_test_calculate_sha256_null);
TEST (hash_kat_test_run_self_test_calculate_sha256_calculate_fail);
TEST (hash_kat_test_run_self_test_calculate_sha384);
#ifdef HASH_ENABLE_SHA384
TEST (hash_kat_test_run_self_test_calculate_sha384_mismatch_data);
TEST (hash_kat_test_run_self_test_calculate_sha384_null);
TEST (hash_kat_test_run_self_test_calculate_sha384_calculate_fail);
#endif
TEST (hash_kat_test_run_self_test_calculate_sha512);
#ifdef HASH_ENABLE_SHA512
TEST (hash_kat_test_run_self_test_calculate_sha512_mismatch_data);
TEST (hash_kat_test_run_self_test_calculate_sha512_null);
TEST (hash_kat_test_run_self_test_calculate_sha512_calculate_fail);
#endif
TEST (hash_kat_test_run_all_calculate_self_tests);
TEST (hash_kat_test_run_all_calculate_self_tests_mock);
TEST (hash_kat_test_run_all_calculate_self_tests_null);
#ifdef HASH_ENABLE_SHA1
TEST (hash_kat_test_run_all_calculate_self_tests_sha1_fail);
#endif
TEST (hash_kat_test_run_all_calculate_self_tests_sha256_fail);
#ifdef HASH_ENABLE_SHA384
TEST (hash_kat_test_run_all_calculate_self_tests_sha384_fail);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (hash_kat_test_run_all_calculate_self_tests_sha512_fail);
#endif
TEST (hash_kat_test_run_self_test_update_sha1);
#ifdef HASH_ENABLE_SHA1
TEST (hash_kat_test_run_self_test_update_sha1_mismatch_data);
TEST (hash_kat_test_run_self_test_update_sha1_null);
TEST (hash_kat_test_run_self_test_update_sha1_start_fail);
TEST (hash_kat_test_run_self_test_update_sha1_update_first_fail);
TEST (hash_kat_test_run_self_test_update_sha1_update_second_fail);
TEST (hash_kat_test_run_self_test_update_sha1_finish_fail);
#endif
TEST (hash_kat_test_run_self_test_update_sha256);
TEST (hash_kat_test_run_self_test_update_sha256_mismatch_data);
TEST (hash_kat_test_run_self_test_update_sha256_null);
TEST (hash_kat_test_run_self_test_update_sha256_start_fail);
TEST (hash_kat_test_run_self_test_update_sha256_update_first_fail);
TEST (hash_kat_test_run_self_test_update_sha256_update_second_fail);
TEST (hash_kat_test_run_self_test_update_sha256_finish_fail);
TEST (hash_kat_test_run_self_test_update_sha384);
#ifdef HASH_ENABLE_SHA384
TEST (hash_kat_test_run_self_test_update_sha384_mismatch_data);
TEST (hash_kat_test_run_self_test_update_sha384_null);
TEST (hash_kat_test_run_self_test_update_sha384_start_fail);
TEST (hash_kat_test_run_self_test_update_sha384_update_first_fail);
TEST (hash_kat_test_run_self_test_update_sha384_update_second_fail);
TEST (hash_kat_test_run_self_test_update_sha384_finish_fail);
#endif
TEST (hash_kat_test_run_self_test_update_sha512);
#ifdef HASH_ENABLE_SHA512
TEST (hash_kat_test_run_self_test_update_sha512_mismatch_data);
TEST (hash_kat_test_run_self_test_update_sha512_null);
TEST (hash_kat_test_run_self_test_update_sha512_start_fail);
TEST (hash_kat_test_run_self_test_update_sha512_update_first_fail);
TEST (hash_kat_test_run_self_test_update_sha512_update_second_fail);
TEST (hash_kat_test_run_self_test_update_sha512_finish_fail);
#endif
TEST (hash_kat_test_run_all_update_self_tests);
TEST (hash_kat_test_run_all_update_self_tests_mock);
TEST (hash_kat_test_run_all_update_self_tests_null);
#ifdef HASH_ENABLE_SHA1
TEST (hash_kat_test_run_all_update_self_tests_sha1_fail);
#endif
TEST (hash_kat_test_run_all_update_self_tests_sha256_fail);
#ifdef HASH_ENABLE_SHA384
TEST (hash_kat_test_run_all_update_self_tests_sha384_fail);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (hash_kat_test_run_all_update_self_tests_sha512_fail);
#endif
TEST (hash_kat_test_hmac_run_self_test_sha1);
#ifdef HASH_ENABLE_SHA1
TEST (hash_kat_test_hmac_run_self_test_sha1_mismatch_data);
TEST (hash_kat_test_hmac_run_self_test_sha1_null);
TEST (hash_kat_test_hmac_run_self_test_sha1_calculate_fail);
#endif
TEST (hash_kat_test_hmac_run_self_test_sha256);
TEST (hash_kat_test_hmac_run_self_test_sha256_mismatch_data);
TEST (hash_kat_test_hmac_run_self_test_sha256_null);
TEST (hash_kat_test_hmac_run_self_test_sha256_calculate_fail);
TEST (hash_kat_test_hmac_run_self_test_sha384);
#ifdef HASH_ENABLE_SHA384
TEST (hash_kat_test_hmac_run_self_test_sha384_mismatch_data);
TEST (hash_kat_test_hmac_run_self_test_sha384_null);
TEST (hash_kat_test_hmac_run_self_test_sha384_calculate_fail);
#endif
TEST (hash_kat_test_hmac_run_self_test_sha512);
#ifdef HASH_ENABLE_SHA512
TEST (hash_kat_test_hmac_run_self_test_sha512_mismatch_data);
TEST (hash_kat_test_hmac_run_self_test_sha512_null);
TEST (hash_kat_test_hmac_run_self_test_sha512_calculate_fail);
#endif
TEST (hash_kat_test_hmac_run_all_self_tests);
TEST (hash_kat_test_hmac_run_all_self_tests_mock);
TEST (hash_kat_test_hmac_run_all_self_tests_null);
#ifdef HASH_ENABLE_SHA1
TEST (hash_kat_test_hmac_run_all_self_tests_sha1_fail);
#endif
TEST (hash_kat_test_hmac_run_all_self_tests_sha256_fail);
#ifdef HASH_ENABLE_SHA384
TEST (hash_kat_test_hmac_run_all_self_tests_sha384_fail);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (hash_kat_test_hmac_run_all_self_tests_sha512_fail);
#endif

TEST_SUITE_END;
// *INDENT-ON*
