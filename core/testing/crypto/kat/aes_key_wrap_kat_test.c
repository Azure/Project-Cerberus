// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/aes_key_wrap.h"
#include "crypto/aes_key_wrap_with_padding.h"
#include "crypto/kat/aes_key_wrap_kat.h"
#include "crypto/kat/aes_key_wrap_kat_vectors.h"
#include "testing/engines/aes_testing_engine.h"
#include "testing/mock/crypto/aes_key_wrap_mock.h"


TEST_SUITE_LABEL ("aes_key_wrap_kat");


/**
 * Block aligned length of the data used for AES Key Wrap with Padding tests.
 */
#define	AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN	16


/*******************
 * Test cases
 *******************/

static void aes_key_wrap_kat_test_run_self_test_wrap_aes256 (CuTest *test)
{
	AES_ECB_TESTING_ENGINE (ecb);
	struct aes_key_wrap aes_kw;
	int status;

	TEST_START;

	status = AES_ECB_TESTING_ENGINE_INIT (&ecb);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_init (&aes_kw, &ecb.base);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_release (&aes_kw);
	AES_ECB_TESTING_ENGINE_RELEASE (&ecb);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_aes256_data_mismatch (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	int status;
	uint8_t bad_wrap[AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN];

	TEST_START;

	memcpy (bad_wrap, AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED, sizeof (bad_wrap));
	bad_wrap[7] ^= 0xff;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.wrap, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN));
	status |= mock_expect_output (&aes_kw.mock, 2, bad_wrap, sizeof (bad_wrap), 3);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_key_wrap_kat_run_self_test_wrap_aes256 (NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_aes256_set_kek_error (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, AES_KEY_WRAP_SET_KEK_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SET_KEK_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_aes256_wrap_error (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.wrap, &aes_kw, AES_KEY_WRAP_WRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_WRAP_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_aes256_clear_kek_error (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.wrap, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN));
	status |= mock_expect_output (&aes_kw.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN, 3);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_CLEAR_KEK_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_aes256_clear_kek_error_after_wrap_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.wrap, &aes_kw, AES_KEY_WRAP_WRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN));
	status |= mock_expect_output (&aes_kw.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN, 3);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_WRAP_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_aes256_clear_kek_error_after_data_mismatch (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	int status;
	uint8_t bad_wrap[AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN];

	TEST_START;

	memcpy (bad_wrap, AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED, sizeof (bad_wrap));
	bad_wrap[7] ^= 0xff;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.wrap, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN));
	status |= mock_expect_output (&aes_kw.mock, 2, bad_wrap, sizeof (bad_wrap), 3);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256 (CuTest *test)
{
	AES_ECB_TESTING_ENGINE (ecb);
	struct aes_key_wrap aes_kw;
	int status;

	TEST_START;

	status = AES_ECB_TESTING_ENGINE_INIT (&ecb);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_init (&aes_kw, &ecb.base);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_release (&aes_kw);
	AES_ECB_TESTING_ENGINE_RELEASE (&ecb);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_length_mismatch (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	size_t in_length = AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN;
	size_t out_length = in_length - 1;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.unwrap, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kw.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN, -1);
	status |= mock_expect_output (&aes_kw.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_data_mismatch (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	size_t in_length = AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN;
	size_t out_length = in_length;
	int status;
	uint8_t bad_unwrap[AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN];

	TEST_START;

	memcpy (bad_unwrap, AES_KEY_WRAP_KAT_VECTORS_KW_DATA, sizeof (bad_unwrap));
	bad_unwrap[7] ^= 0xff;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.unwrap, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kw.mock, 2, bad_unwrap, sizeof (bad_unwrap), -1);
	status |= mock_expect_output (&aes_kw.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_set_kek_error (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, AES_KEY_WRAP_SET_KEK_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SET_KEK_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_unwrap_error (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	size_t in_length = AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.unwrap, &aes_kw, AES_KEY_WRAP_UNWRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_UNWRAP_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_clear_kek_error (CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	size_t in_length = AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN;
	size_t out_length = in_length;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.unwrap, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kw.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN, -1);
	status |= mock_expect_output (&aes_kw.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_CLEAR_KEK_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_clear_kek_error_after_unwrap_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	size_t in_length = AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.unwrap, &aes_kw, AES_KEY_WRAP_UNWRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_UNWRAP_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_clear_kek_error_after_length_mismatch
	(CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	size_t in_length = AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN;
	size_t out_length = in_length - 1;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.unwrap, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kw.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KW_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN, -1);
	status |= mock_expect_output (&aes_kw.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_aes256_clear_kek_error_after_data_mismatch (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kw;
	size_t in_length = AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN;
	size_t out_length = in_length;
	int status;
	uint8_t bad_unwrap[AES_KEY_WRAP_KAT_VECTORS_KW_DATA_LEN];

	TEST_START;

	memcpy (bad_unwrap, AES_KEY_WRAP_KAT_VECTORS_KW_DATA, sizeof (bad_unwrap));
	bad_unwrap[7] ^= 0xff;

	status = aes_key_wrap_mock_init (&aes_kw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kw.mock, aes_kw.base.set_kek, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_KEY_LEN));

	status |= mock_expect (&aes_kw.mock, aes_kw.base.unwrap, &aes_kw, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KW_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kw.mock, 2, bad_unwrap, sizeof (bad_unwrap), -1);
	status |= mock_expect_output (&aes_kw.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kw.mock, aes_kw.base.clear_kek, &aes_kw,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_aes256 (&aes_kw.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kw);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256 (CuTest *test)
{
	AES_ECB_TESTING_ENGINE (ecb);
	struct aes_key_wrap_with_padding aes_kwp;
	int status;

	TEST_START;

	status = AES_ECB_TESTING_ENGINE_INIT (&ecb);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_with_padding_init (&aes_kwp, &ecb.base);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (&aes_kwp.base.base);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_release (&aes_kwp);
	AES_ECB_TESTING_ENGINE_RELEASE (&ecb);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_data_mismatch (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	int status;
	uint8_t bad_wrap[AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN];

	TEST_START;

	memcpy (bad_wrap, AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED, sizeof (bad_wrap));
	bad_wrap[7] ^= 0xff;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.wrap, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN));
	status |= mock_expect_output (&aes_kwp.mock, 2, bad_wrap, sizeof (bad_wrap), 3);

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_set_kek_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp,
		AES_KEY_WRAP_SET_KEK_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SET_KEK_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_wrap_error (CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.wrap, &aes_kwp, AES_KEY_WRAP_WRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_WRAP_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_clear_kek_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.wrap, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN));
	status |= mock_expect_output (&aes_kwp.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN, 3);

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_CLEAR_KEK_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void
aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_clear_kek_error_after_wrap_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.wrap, &aes_kwp, AES_KEY_WRAP_WRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_WRAP_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void
aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_clear_kek_error_after_data_mismatch (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	int status;
	uint8_t bad_wrap[AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN];

	TEST_START;

	memcpy (bad_wrap, AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED, sizeof (bad_wrap));
	bad_wrap[7] ^= 0xff;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.wrap, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN));
	status |= mock_expect_output (&aes_kwp.mock, 2, bad_wrap, sizeof (bad_wrap), 3);

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_wrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256 (CuTest *test)
{
	AES_ECB_TESTING_ENGINE (ecb);
	struct aes_key_wrap_with_padding aes_kwp;
	int status;

	TEST_START;

	status = AES_ECB_TESTING_ENGINE_INIT (&ecb);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_with_padding_init (&aes_kwp, &ecb.base);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base.base);
	CuAssertIntEquals (test, 0, status);

	aes_key_wrap_with_padding_release (&aes_kwp);
	AES_ECB_TESTING_ENGINE_RELEASE (&ecb);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_length_mismatch (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	size_t in_length = AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN;
	size_t out_length = AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN - 1;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.unwrap, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kwp.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN, -1);
	status |= mock_expect_output (&aes_kwp.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_data_mismatch (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	size_t in_length = AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN;
	size_t out_length = AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN;
	int status;
	uint8_t bad_unwrap[AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN] = {0};

	TEST_START;

	memcpy (bad_unwrap, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN);
	bad_unwrap[7] ^= 0xff;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.unwrap, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kwp.mock, 2, bad_unwrap, sizeof (bad_unwrap), -1);
	status |= mock_expect_output (&aes_kwp.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (NULL);
	CuAssertIntEquals (test, AES_KEY_WRAP_INVALID_ARGUMENT, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_set_kek_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp,
		AES_KEY_WRAP_SET_KEK_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SET_KEK_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_unwrap_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	size_t in_length = AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.unwrap, &aes_kwp, AES_KEY_WRAP_UNWRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp, 0);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_UNWRAP_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_clear_kek_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	size_t in_length = AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN;
	size_t out_length = AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.unwrap, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kwp.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN, -1);
	status |= mock_expect_output (&aes_kwp.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_CLEAR_KEK_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void
aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_clear_kek_error_after_unwrap_error (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	size_t in_length = AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.unwrap, &aes_kwp, AES_KEY_WRAP_UNWRAP_FAILED,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_UNWRAP_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void
aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_clear_kek_error_after_length_mismatch
(
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	size_t in_length = AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN;
	size_t out_length = AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN - 1;
	int status;

	TEST_START;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.unwrap, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kwp.mock, 2, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA,
		AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN, -1);
	status |= mock_expect_output (&aes_kwp.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}

static void
aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_clear_kek_error_after_data_mismatch (
	CuTest *test)
{
	struct aes_key_wrap_mock aes_kwp;
	size_t in_length = AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN;
	size_t out_length = AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN;
	int status;
	uint8_t bad_unwrap[AES_KEY_WRAP_KAT_TESTING_KWP_ALIGNED_DATA_LEN] = {0};

	TEST_START;

	memcpy (bad_unwrap, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA, AES_KEY_WRAP_KAT_VECTORS_KWP_DATA_LEN);
	bad_unwrap[7] ^= 0xff;

	status = aes_key_wrap_mock_init (&aes_kwp);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_kwp.mock, aes_kwp.base.set_kek, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY,
		AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN), MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_KEY_LEN));

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.unwrap, &aes_kwp, 0,
		MOCK_ARG_PTR_CONTAINS (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED,
		AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN),
		MOCK_ARG (AES_KEY_WRAP_KAT_VECTORS_KWP_WRAPPED_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&aes_kwp.mock, 2, bad_unwrap, sizeof (bad_unwrap), -1);
	status |= mock_expect_output (&aes_kwp.mock, 3, &out_length, sizeof (out_length), -1);

	status |= mock_expect (&aes_kwp.mock, aes_kwp.base.clear_kek, &aes_kwp,
		AES_KEY_WRAP_CLEAR_KEK_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_kat_run_self_test_unwrap_with_padding_aes256 (&aes_kwp.base);
	CuAssertIntEquals (test, AES_KEY_WRAP_SELF_TEST_FAILED, status);

	status = aes_key_wrap_mock_validate_and_release (&aes_kwp);
	CuAssertIntEquals (test, 0, status);
}


// *INDENT-OFF*
TEST_SUITE_START (aes_key_wrap_kat);

TEST (aes_key_wrap_kat_test_run_self_test_wrap_aes256);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_aes256_data_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_aes256_null);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_aes256_set_kek_error);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_aes256_wrap_error);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_aes256_clear_kek_error);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_aes256_clear_kek_error_after_wrap_error);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_aes256_clear_kek_error_after_data_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_length_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_data_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_null);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_set_kek_error);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_unwrap_error);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_clear_kek_error);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_clear_kek_error_after_unwrap_error);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_clear_kek_error_after_length_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_aes256_clear_kek_error_after_data_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_data_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_null);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_set_kek_error);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_wrap_error);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_clear_kek_error);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_clear_kek_error_after_wrap_error);
TEST (aes_key_wrap_kat_test_run_self_test_wrap_with_padding_aes256_clear_kek_error_after_data_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_length_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_data_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_null);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_set_kek_error);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_unwrap_error);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_clear_kek_error);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_clear_kek_error_after_unwrap_error);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_clear_kek_error_after_length_mismatch);
TEST (aes_key_wrap_kat_test_run_self_test_unwrap_with_padding_aes256_clear_kek_error_after_data_mismatch);

TEST_SUITE_END;
// *INDENT-ON*
