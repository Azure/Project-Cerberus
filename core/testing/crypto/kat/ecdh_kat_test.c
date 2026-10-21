// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/kat/ecc_kat_vectors.h"
#include "crypto/kat/ecdh_kat.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/mock/crypto/ecc_hw_mock.h"
#include "testing/mock/crypto/ecc_mock.h"


TEST_SUITE_LABEL ("ecdh_kat");

/*******************
 * Test cases
 *******************/

static void ecdh_kat_test_self_test_p256 (CuTest *test)
{
	int status;

	ECC_TESTING_ENGINE (ecc);

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p256 (&ecc.base);
	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void ecdh_kat_test_self_test_p256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = ecdh_kat_run_self_test_p256 (NULL);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);
}

static void ecdh_kat_test_self_test_p256_init_key_fail (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p256 (&ecc.base);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_kat_test_self_test_p256_compute_fail (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.compute_shared_secret, &ecc.base,
		ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc.base, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p256 (&ecc.base);
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_kat_test_self_test_p256_mismatch (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;
	uint8_t shared_secret[ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN] = {};

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.compute_shared_secret, &ecc.base,
		ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc.mock, 2, shared_secret, sizeof (shared_secret), -1);
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc.base, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p256 (&ecc.base);
	CuAssertIntEquals (test, ECDH_P256_SELF_TEST_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_kat_test_self_test_p384 (CuTest *test)
{
	int status;

	ECC_TESTING_ENGINE (ecc);

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p384 (&ecc.base);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECDH_UNSUPPORTED_SELF_TEST, status);
#endif

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecdh_kat_test_self_test_p384_null (CuTest *test)
{
	int status;

	TEST_START;

	status = ecdh_kat_run_self_test_p384 (NULL);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);
}

static void ecdh_kat_test_self_test_p384_init_key_fail (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p384 (&ecc.base);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_kat_test_self_test_p384_compute_fail (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.compute_shared_secret, &ecc.base,
		ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc.base, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p384 (&ecc.base);
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_kat_test_self_test_p384_mismatch (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;
	uint8_t shared_secret[ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN] = {};

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.compute_shared_secret, &ecc.base,
		ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc.mock, 2, shared_secret, sizeof (shared_secret), -1);
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc.base, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p384 (&ecc.base);
	CuAssertIntEquals (test, ECDH_P384_SELF_TEST_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void ecdh_kat_test_self_test_p521 (CuTest *test)
{
	int status;

	ECC_TESTING_ENGINE (ecc);

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p521 (&ecc.base);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECDH_UNSUPPORTED_SELF_TEST, status);
#endif

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecdh_kat_test_self_test_p521_null (CuTest *test)
{
	int status;

	TEST_START;

	status = ecdh_kat_run_self_test_p521 (NULL);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);
}

static void ecdh_kat_test_self_test_p521_init_key_fail (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p521 (&ecc.base);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_kat_test_self_test_p521_compute_fail (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.compute_shared_secret, &ecc.base,
		ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc.base, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p521 (&ecc.base);
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_kat_test_self_test_p521_mismatch (CuTest *test)
{
	int status;
	struct ecc_engine_mock ecc;
	uint8_t shared_secret[ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN] = {};

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.compute_shared_secret, &ecc.base,
		ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN, MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc.mock, 2, shared_secret, sizeof (shared_secret), -1);
	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc.base, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_kat_run_self_test_p521 (&ecc.base);
	CuAssertIntEquals (test, ECDH_P521_SELF_TEST_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void ecdh_hw_kat_test_self_test_p256 (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P256_ECC_PRIVATE), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR (&ECC_KAT_VECTORS_P256_ECC_PUBLIC), MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_hw_kat_run_self_test_p256 (&ecc_hw.base);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_hw_kat_test_self_test_p256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = ecdh_hw_kat_run_self_test_p256 (NULL);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);
}

static void ecdh_hw_kat_test_self_test_p256_compute_fail (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base,
		ECC_HW_ECDH_COMPUTE_FAILED,	MOCK_ARG_PTR (ECC_KAT_VECTORS_P256_ECC_PRIVATE),
		MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&ECC_KAT_VECTORS_P256_ECC_PUBLIC),
		MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_hw_kat_run_self_test_p256 (&ecc_hw.base);
	CuAssertIntEquals (test, ECC_HW_ECDH_COMPUTE_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_hw_kat_test_self_test_p256_mismatch (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;
	uint8_t zero_shared_secret[ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN] = {};

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P256_ECC_PRIVATE), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR (&ECC_KAT_VECTORS_P256_ECC_PUBLIC), MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, zero_shared_secret,
		ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_hw_kat_run_self_test_p256 (&ecc_hw.base);
	CuAssertIntEquals (test, ECDH_P256_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_hw_kat_test_self_test_p384 (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR (&ECC_KAT_VECTORS_P384_ECC_PUBLIC), MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);
#endif

	status = ecdh_hw_kat_run_self_test_p384 (&ecc_hw.base);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECDH_UNSUPPORTED_SELF_TEST, status);
#endif

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
static void ecdh_hw_kat_test_self_test_p384_null (CuTest *test)
{
	int status;

	TEST_START;

	status = ecdh_hw_kat_run_self_test_p384 (NULL);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);
}

static void ecdh_hw_kat_test_self_test_p384_compute_fail (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base,
		ECC_HW_ECDH_COMPUTE_FAILED,	MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE),
		MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_PTR (&ECC_KAT_VECTORS_P384_ECC_PUBLIC),
		MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_hw_kat_run_self_test_p384 (&ecc_hw.base);
	CuAssertIntEquals (test, ECC_HW_ECDH_COMPUTE_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_hw_kat_test_self_test_p384_mismatch (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;
	uint8_t zero_shared_secret[ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN] = {};

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P384_ECC_PRIVATE), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR (&ECC_KAT_VECTORS_P384_ECC_PUBLIC), MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, zero_shared_secret,
		ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_hw_kat_run_self_test_p384 (&ecc_hw.base);
	CuAssertIntEquals (test, ECDH_P384_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}
#endif

static void ecdh_hw_kat_test_self_test_p521 (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P521_ECC_PRIVATE), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR (&ECC_KAT_VECTORS_P521_ECC_PUBLIC), MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);
#endif

	status = ecdh_hw_kat_run_self_test_p521 (&ecc_hw.base);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECDH_UNSUPPORTED_SELF_TEST, status);
#endif

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}

#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
static void ecdh_hw_kat_test_self_test_p521_null (CuTest *test)
{
	int status;

	TEST_START;

	status = ecdh_hw_kat_run_self_test_p521 (NULL);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);
}

static void ecdh_hw_kat_test_self_test_p521_compute_fail (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base,
		ECC_HW_ECDH_COMPUTE_FAILED,	MOCK_ARG_PTR (ECC_KAT_VECTORS_P521_ECC_PRIVATE),
		MOCK_ARG (ECC_KEY_LENGTH_521), MOCK_ARG_PTR (&ECC_KAT_VECTORS_P521_ECC_PUBLIC),
		MOCK_ARG_NOT_NULL, MOCK_ARG (ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_hw_kat_run_self_test_p521 (&ecc_hw.base);
	CuAssertIntEquals (test, ECC_HW_ECDH_COMPUTE_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}

static void ecdh_hw_kat_test_self_test_p521_mismatch (CuTest *test)
{
	int status;
	struct ecc_hw_mock ecc_hw;
	uint8_t zero_shared_secret[ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN] = {};

	TEST_START;

	status = ecc_hw_mock_init (&ecc_hw);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc_hw.mock, ecc_hw.base.ecdh_compute, &ecc_hw.base, 0,
		MOCK_ARG_PTR (ECC_KAT_VECTORS_P521_ECC_PRIVATE), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR (&ECC_KAT_VECTORS_P521_ECC_PUBLIC), MOCK_ARG_NOT_NULL,
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN));
	status |= mock_expect_output (&ecc_hw.mock, 3, zero_shared_secret,
		ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET_LEN, -1);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_hw_kat_run_self_test_p521 (&ecc_hw.base);
	CuAssertIntEquals (test, ECDH_P521_SELF_TEST_FAILED, status);

	status = ecc_hw_mock_validate_and_release (&ecc_hw);
	CuAssertIntEquals (test, 0, status);
}
#endif

// *INDENT-OFF*
TEST_SUITE_START (ecdh_kat);

TEST (ecdh_kat_test_self_test_p256);
TEST (ecdh_kat_test_self_test_p256_null);
TEST (ecdh_kat_test_self_test_p256_init_key_fail);
TEST (ecdh_kat_test_self_test_p256_compute_fail);
TEST (ecdh_kat_test_self_test_p256_mismatch);

TEST (ecdh_kat_test_self_test_p384);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecdh_kat_test_self_test_p384_null);
TEST (ecdh_kat_test_self_test_p384_init_key_fail);
TEST (ecdh_kat_test_self_test_p384_compute_fail);
TEST (ecdh_kat_test_self_test_p384_mismatch);
#endif

TEST (ecdh_kat_test_self_test_p521);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecdh_kat_test_self_test_p521_null);
TEST (ecdh_kat_test_self_test_p521_init_key_fail);
TEST (ecdh_kat_test_self_test_p521_compute_fail);
TEST (ecdh_kat_test_self_test_p521_mismatch);
#endif

TEST (ecdh_hw_kat_test_self_test_p256);
TEST (ecdh_hw_kat_test_self_test_p256_null);
TEST (ecdh_hw_kat_test_self_test_p256_compute_fail);
TEST (ecdh_hw_kat_test_self_test_p256_mismatch);

TEST (ecdh_hw_kat_test_self_test_p384);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384
TEST (ecdh_hw_kat_test_self_test_p384_null);
TEST (ecdh_hw_kat_test_self_test_p384_compute_fail);
TEST (ecdh_hw_kat_test_self_test_p384_mismatch);
#endif

TEST (ecdh_hw_kat_test_self_test_p521);
#if ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521
TEST (ecdh_hw_kat_test_self_test_p521_null);
TEST (ecdh_hw_kat_test_self_test_p521_compute_fail);
TEST (ecdh_hw_kat_test_self_test_p521_mismatch);
#endif

TEST_SUITE_END;
// *INDENT-ON*
