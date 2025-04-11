// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "crypto/ecdh.h"
#include "crypto/kat/ecc_kat_vectors.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/mock/crypto/ecc_hw_mock.h"
#include "testing/mock/crypto/ecc_mock.h"


TEST_SUITE_LABEL ("ecdh");


/**
 * Test dependencies for ECDH.
 */
struct ecdh_testing {
	ECC_TESTING_ENGINE (ecc);			/**< ECC engine for test. */
	struct ecc_engine_mock ecc_mock;	/**< Mock for the ECC engine. */
	struct ecc_hw_mock ecc_hw;			/**< Mock for the ECC HW driver. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param ecdh Testing dependencies to initialize.
 */
static void ecdh_testing_init_dependencies (CuTest *test, struct ecdh_testing *ecdh)
{
	int status;

	status = ECC_TESTING_ENGINE_INIT (&ecdh->ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecdh->ecc_mock);
	CuAssertIntEquals (test, 0, status);

	status = ecc_hw_mock_init (&ecdh->ecc_hw);
	CuAssertIntEquals (test, 0, status);

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
	ecdh_fail_pct = false;
	ecdh_hw_fail_pct = false;
#endif
}

/**
 * Helper to release all testing dependencies.
 *
 * @param test The test framework.
 * @param ecdh Testing dependencies to release.
 */
static void ecdh_testing_release_dependencies (CuTest *test, struct ecdh_testing *ecdh)
{
	int status;

	status = ecc_mock_validate_and_release (&ecdh->ecc_mock);
	status |= ecc_hw_mock_validate_and_release (&ecdh->ecc_hw);

	CuAssertIntEquals (test, 0, status);

	ECC_TESTING_ENGINE_RELEASE (&ecdh->ecc);
}


/*******************
 * Test cases
 *******************/

static void ecdh_test_generate_random_key_p256 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_generate_random_key (&ecdh.ecc.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_mock_p256 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_generate_random_key_p256_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	ecdh_fail_pct = true;

	status = ecdh_generate_random_key (&ecdh.ecc.base, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif

static void ecdh_test_generate_random_key_p384 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_generate_random_key (&ecdh.ecc.base, ECC_KEY_LENGTH_384, &priv_key, &pub_key);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	ecdh_testing_release_dependencies (test, &ecdh);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void ecdh_test_generate_random_key_mock_p384 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_384, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_384, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_384, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_384, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_generate_random_key_p384_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	ecdh_fail_pct = true;

	status = ecdh_generate_random_key (&ecdh.ecc.base, ECC_KEY_LENGTH_384, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif
#endif

static void ecdh_test_generate_random_key_p521 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_generate_random_key (&ecdh.ecc.base, ECC_KEY_LENGTH_521, &priv_key, &pub_key);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);
	CuAssertPtrNotNull (test, pub_key.context);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);
#else
	CuAssertIntEquals (test, ECC_ENGINE_UNSUPPORTED_KEY_LENGTH, status);
#endif

	ecdh_testing_release_dependencies (test, &ecdh);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void ecdh_test_generate_random_key_mock_p521 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_521), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_521, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_521, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_521, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_521, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_generate_random_key_p521_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	ecdh_fail_pct = true;

	status = ecdh_generate_random_key (&ecdh.ecc.base, ECC_KEY_LENGTH_521, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif
#endif

static void ecdh_test_generate_random_key_no_public_key (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_generate_random_key (&ecdh.ecc.base, ECC_KEY_LENGTH_256, &priv_key, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, priv_key.context);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, NULL);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_null (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_generate_random_key (NULL, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	status = ecdh_generate_random_key (&ecdh.ecc.base, ECC_KEY_LENGTH_256, NULL, &pub_key);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_generate_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		ECC_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key),
		MOCK_ARG_PTR (&pub_key));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_GENERATE_KEY_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_pct_key_length_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 1, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_ENGINE_SECRET_LENGTH_FAILED, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_SECRET_LENGTH_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_pct_init_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 1, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_pct_priv_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 1, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_PTR (&priv_key),
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));
	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_pct_pub_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 1, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_PTR (&pub_key), MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));
	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_pct_data_mismatch (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t bad_pct[ECC_KEY_LENGTH_256];

	TEST_START;

	memcpy (bad_pct, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_256);
	bad_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 1, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, bad_pct, ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));
	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_generate_random_key_pct_length_mismatch (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 1, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256 + 1, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));
	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_generate_random_key_cmvp_pct_fault_init_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.generate_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_PTR (&priv_key), MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 1, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (3));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_public_key, &ecdh.ecc_mock,
		ECC_ENGINE_PUBLIC_KEY_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_PTR (NULL));
	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	ecdh_fail_pct = true;

	status = ecdh_generate_random_key (&ecdh.ecc_mock.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_FAILED, status);
	CuAssertIntEquals (test, false, ecdh_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif

static void ecdh_test_ecc_hw_generate_random_key_p256 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC_PUBKEY2_POINT,
		sizeof (ECC_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_PRIVKEY2, priv_key.d, ECC_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC_PRIVKEY2_LEN, priv_key.key_length);

	status = testing_validate_array (ECC_PUBKEY2_POINT.x, pub_key.x, ECC_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_PUBKEY2_POINT.y, pub_key.y, ECC_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC_PRIVKEY2_LEN, pub_key.key_length);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_ecc_hw_generate_random_key_p256_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;
	uint8_t cmvp_fault_priv[ECC_KEY_LENGTH_256];
	uint8_t cmvp_fault_pct[ECC_KEY_LENGTH_256];

	TEST_START;

	memcpy (cmvp_fault_priv, ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256);
	cmvp_fault_priv[16] ^= 0x10;

	memcpy (cmvp_fault_pct, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_256);
	cmvp_fault_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC_PUBKEY2_POINT,
		sizeof (ECC_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (cmvp_fault_priv, ECC_KEY_LENGTH_256), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, cmvp_fault_pct, ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	ecdh_hw_fail_pct = true;

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_hw_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void ecdh_test_ecc_hw_generate_random_key_p384 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC384_PRIVKEY2, ECC384_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC384_PUBKEY2_POINT,
		sizeof (ECC384_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY2, ECC384_PRIVKEY2_LEN),
		MOCK_ARG (ECC384_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P384_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P384_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (&ECC384_PUBKEY2_POINT, sizeof (ECC384_PUBKEY2_POINT)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_384, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_PRIVKEY2, priv_key.d, ECC384_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC384_PRIVKEY2_LEN, priv_key.key_length);

	status = testing_validate_array (ECC384_PUBKEY2_POINT.x, pub_key.x, ECC384_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC384_PUBKEY2_POINT.y, pub_key.y, ECC384_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC384_PRIVKEY2_LEN, pub_key.key_length);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_ecc_hw_generate_random_key_p384_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;
	uint8_t cmvp_fault_priv[ECC_KEY_LENGTH_384];
	uint8_t cmvp_fault_pct[ECC_KEY_LENGTH_384];

	TEST_START;

	memcpy (cmvp_fault_priv, ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384);
	cmvp_fault_priv[16] ^= 0x10;

	memcpy (cmvp_fault_pct, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_384);
	cmvp_fault_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_384), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC384_PRIVKEY2, ECC384_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC384_PUBKEY2_POINT,
		sizeof (ECC384_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY2, ECC384_PRIVKEY2_LEN),
		MOCK_ARG (ECC384_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P384_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P384_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (cmvp_fault_priv, ECC_KEY_LENGTH_384), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (&ECC384_PUBKEY2_POINT, sizeof (ECC384_PUBKEY2_POINT)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, cmvp_fault_pct, ECC_KEY_LENGTH_384, 4);

	CuAssertIntEquals (test, 0, status);

	ecdh_hw_fail_pct = true;

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_384, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_hw_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void ecdh_test_ecc_hw_generate_random_key_p521 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_521), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC521_PRIVKEY2, ECC521_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC521_PUBKEY2_POINT,
		sizeof (ECC521_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY2, ECC521_PRIVKEY2_LEN),
		MOCK_ARG (ECC521_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P521_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P521_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521),
		MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (&ECC521_PUBKEY2_POINT, sizeof (ECC521_PUBKEY2_POINT)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_521, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_PRIVKEY2, priv_key.d, ECC521_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC521_PRIVKEY2_LEN, priv_key.key_length);

	status = testing_validate_array (ECC521_PUBKEY2_POINT.x, pub_key.x, ECC521_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC521_PUBKEY2_POINT.y, pub_key.y, ECC521_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC521_PRIVKEY2_LEN, pub_key.key_length);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_ecc_hw_generate_random_key_p521_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;
	uint8_t cmvp_fault_priv[ECC_KEY_LENGTH_521];
	uint8_t cmvp_fault_pct[ECC_KEY_LENGTH_521];

	TEST_START;

	memcpy (cmvp_fault_priv, ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521);
	cmvp_fault_priv[16] ^= 0x10;

	memcpy (cmvp_fault_pct, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_521);
	cmvp_fault_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_521), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC521_PRIVKEY2, ECC521_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC521_PUBKEY2_POINT,
		sizeof (ECC521_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY2, ECC521_PRIVKEY2_LEN),
		MOCK_ARG (ECC521_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P521_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P521_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (cmvp_fault_priv, ECC_KEY_LENGTH_521), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (&ECC521_PUBKEY2_POINT, sizeof (ECC521_PUBKEY2_POINT)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, cmvp_fault_pct, ECC_KEY_LENGTH_521, 4);

	CuAssertIntEquals (test, 0, status);

	ecdh_hw_fail_pct = true;

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_521, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_hw_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif
#endif

static void ecdh_test_ecc_hw_generate_random_key_no_public_key (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC_PUBKEY2_POINT,
		sizeof (ECC_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_256, &priv_key,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (ECC_PRIVKEY2, priv_key.d, ECC_PRIVKEY2_LEN);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, ECC_PRIVKEY2_LEN, priv_key.key_length);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_generate_random_key_null (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_ecc_hw_generate_random_key (NULL, ECC_KEY_LENGTH_256, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_256, NULL,
		&pub_key);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_generate_random_key_generate_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		ECC_HW_ECC_GENERATE_FAILED, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR (&pub_key));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_HW_ECC_GENERATE_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_generate_random_key_pct_priv_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC_PUBKEY2_POINT,
		sizeof (ECC_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw,
		ECC_HW_ECDH_COMPUTE_FAILED, MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN),
		MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_HW_ECDH_COMPUTE_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_generate_random_key_pct_pub_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC_PUBKEY2_POINT,
		sizeof (ECC_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw,
		ECC_HW_ECDH_COMPUTE_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECC_HW_ECDH_COMPUTE_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_generate_random_key_pct_data_mismatch (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_raw_private_key priv_key;
	struct ecc_point_public_key pub_key;
	int status;
	uint8_t bad_pct[ECC_KEY_LENGTH_256];

	TEST_START;

	memcpy (bad_pct, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_256);
	bad_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.generate_ecc_key_pair, &ecdh.ecc_hw,
		0, MOCK_ARG (ECC_KEY_LENGTH_256), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&pub_key));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 1, ECC_PRIVKEY2, ECC_PRIVKEY2_LEN, -1);
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 2, &ECC_PUBKEY2_POINT,
		sizeof (ECC_PUBKEY2_POINT), -1);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, bad_pct, ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_generate_random_key (&ecdh.ecc_hw.base, ECC_KEY_LENGTH_256, &priv_key,
		&pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_p256 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh.ecc.base.init_key_pair (&ecdh.ecc.base, ECC_PRIVKEY2_DER, ECC_PRIVKEY2_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_mock_p256 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_pairwise_consistency_test_p256_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	ecdh_fail_pct = true;

	status = ecdh.ecc.base.init_key_pair (&ecdh.ecc.base, ECC_PRIVKEY2_DER, ECC_PRIVKEY2_DER_LEN,
		&priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_fail_pct);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void ecdh_test_pairwise_consistency_test_p384 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh.ecc.base.init_key_pair (&ecdh.ecc.base, ECC384_PRIVKEY2_DER,
		ECC384_PRIVKEY2_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_mock_p384 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_384, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_384, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_384, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_pairwise_consistency_test_p384_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	ecdh_fail_pct = true;

	status = ecdh.ecc.base.init_key_pair (&ecdh.ecc.base, ECC384_PRIVKEY2_DER,
		ECC384_PRIVKEY2_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_fail_pct);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void ecdh_test_pairwise_consistency_test_p521 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh.ecc.base.init_key_pair (&ecdh.ecc.base, ECC521_PRIVKEY2_DER,
		ECC521_PRIVKEY2_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_mock_p521 (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_521, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 0);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 1);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_521, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_521, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_SAVED_ARG (1));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_pairwise_consistency_test_p521_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	ecdh_fail_pct = true;

	status = ecdh.ecc.base.init_key_pair (&ecdh.ecc.base, ECC521_PRIVKEY2_DER,
		ECC521_PRIVKEY2_DER_LEN, &priv_key, &pub_key);
	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_fail_pct);

	ecdh.ecc.base.release_key_pair (&ecdh.ecc.base, &priv_key, &pub_key);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif
#endif

static void ecdh_test_pairwise_consistency_test_null (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_pairwise_consistency_test (NULL, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc.base, NULL, &pub_key);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_key_length_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_ENGINE_SECRET_LENGTH_FAILED, MOCK_ARG_PTR (&priv_key));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_SECRET_LENGTH_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_init_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_priv_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_PTR (&priv_key),
		MOCK_ARG_SAVED_ARG (3), MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_pub_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_ENGINE_SHARED_SECRET_FAILED, MOCK_ARG_SAVED_ARG (2),
		MOCK_ARG_PTR (&pub_key), MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_SHARED_SECRET_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_data_mismatch (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;
	uint8_t bad_pct[ECC_KEY_LENGTH_256];

	TEST_START;

	memcpy (bad_pct, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_256);
	bad_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, bad_pct, ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_pairwise_consistency_test_length_mismatch (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256 + 1, MOCK_ARG_PTR (&priv_key), MOCK_ARG_SAVED_ARG (3),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.compute_shared_secret,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_PTR (&pub_key),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_mock.mock, 2, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_SAVED_ARG (3));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_pairwise_consistency_test_cmvp_pct_fault_init_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	struct ecc_private_key priv_key;
	struct ecc_public_key pub_key;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.get_shared_secret_max_length,
		&ecdh.ecc_mock, ECC_KEY_LENGTH_256, MOCK_ARG_PTR (&priv_key));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_key_pair, &ecdh.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER,
		ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PRIVATE_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 2, 2);
	status |= mock_expect_save_arg (&ecdh.ecc_mock.mock, 3, 3);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_PTR (NULL), MOCK_ARG_SAVED_ARG (3));

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.init_public_key, &ecdh.ecc_mock,
		ECC_ENGINE_PUBLIC_KEY_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY, MOCK_ARG_NOT_NULL);

	status |= mock_expect (&ecdh.ecc_mock.mock, ecdh.ecc_mock.base.release_key_pair, &ecdh.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	ecdh_fail_pct = true;

	status = ecdh_pairwise_consistency_test (&ecdh.ecc_mock.base, &priv_key, &pub_key);
	CuAssertIntEquals (test, ECC_ENGINE_PUBLIC_KEY_FAILED, status);
	CuAssertIntEquals (test, false, ecdh_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif

static void ecdh_test_ecc_hw_pairwise_consistency_test_p256 (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC_PRIVKEY2,
		ECC_KEY_LENGTH_256, &ECC_PUBKEY2_POINT);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_ecc_hw_pairwise_consistency_test_p256_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;
	uint8_t cmvp_fault_priv[ECC_KEY_LENGTH_256];
	uint8_t cmvp_fault_pct[ECC_KEY_LENGTH_256];

	TEST_START;

	memcpy (cmvp_fault_priv, ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256);
	cmvp_fault_priv[16] ^= 0x10;

	memcpy (cmvp_fault_pct, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_256);
	cmvp_fault_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (cmvp_fault_priv, ECC_KEY_LENGTH_256), MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, cmvp_fault_pct, ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	ecdh_hw_fail_pct = true;

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC_PRIVKEY2,
		ECC_KEY_LENGTH_256, &ECC_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_hw_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void ecdh_test_ecc_hw_pairwise_consistency_test_p384 (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY2, ECC384_PRIVKEY2_LEN),
		MOCK_ARG (ECC384_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P384_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P384_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384),
		MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (&ECC384_PUBKEY2_POINT, sizeof (ECC384_PUBKEY2_POINT)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC384_PRIVKEY2,
		ECC_KEY_LENGTH_384, &ECC384_PUBKEY2_POINT);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_ecc_hw_pairwise_consistency_test_p384_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;
	uint8_t cmvp_fault_priv[ECC_KEY_LENGTH_384];
	uint8_t cmvp_fault_pct[ECC_KEY_LENGTH_384];

	TEST_START;

	memcpy (cmvp_fault_priv, ECC_KAT_VECTORS_P384_ECC_PRIVATE, ECC_KEY_LENGTH_384);
	cmvp_fault_priv[16] ^= 0x10;

	memcpy (cmvp_fault_pct, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_384);
	cmvp_fault_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC384_PRIVKEY2, ECC384_PRIVKEY2_LEN),
		MOCK_ARG (ECC384_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P384_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P384_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P384_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_384, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (cmvp_fault_priv, ECC_KEY_LENGTH_384), MOCK_ARG (ECC_KEY_LENGTH_384),
		MOCK_ARG_PTR_CONTAINS (&ECC384_PUBKEY2_POINT, sizeof (ECC384_PUBKEY2_POINT)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_384));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, cmvp_fault_pct, ECC_KEY_LENGTH_384, 4);

	CuAssertIntEquals (test, 0, status);

	ecdh_hw_fail_pct = true;

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC384_PRIVKEY2,
		ECC_KEY_LENGTH_384, &ECC384_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_hw_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void ecdh_test_ecc_hw_pairwise_consistency_test_p521 (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY2, ECC521_PRIVKEY2_LEN),
		MOCK_ARG (ECC521_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P521_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P521_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521),
		MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (&ECC521_PUBKEY2_POINT, sizeof (ECC521_PUBKEY2_POINT)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC521_PRIVKEY2,
		ECC_KEY_LENGTH_521, &ECC521_PUBKEY2_POINT);
	CuAssertIntEquals (test, 0, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
static void ecdh_test_ecc_hw_pairwise_consistency_test_p521_cmvp_pct_fault (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;
	uint8_t cmvp_fault_priv[ECC_KEY_LENGTH_521];
	uint8_t cmvp_fault_pct[ECC_KEY_LENGTH_521];

	TEST_START;

	memcpy (cmvp_fault_priv, ECC_KAT_VECTORS_P521_ECC_PRIVATE, ECC_KEY_LENGTH_521);
	cmvp_fault_priv[16] ^= 0x10;

	memcpy (cmvp_fault_pct, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_521);
	cmvp_fault_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC521_PRIVKEY2, ECC521_PRIVKEY2_LEN),
		MOCK_ARG (ECC521_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P521_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P521_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P521_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_521, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (cmvp_fault_priv, ECC_KEY_LENGTH_521), MOCK_ARG (ECC_KEY_LENGTH_521),
		MOCK_ARG_PTR_CONTAINS (&ECC521_PUBKEY2_POINT, sizeof (ECC521_PUBKEY2_POINT)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_521));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, cmvp_fault_pct, ECC_KEY_LENGTH_521, 4);

	CuAssertIntEquals (test, 0, status);

	ecdh_hw_fail_pct = true;

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC521_PRIVKEY2,
		ECC_KEY_LENGTH_521, &ECC521_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);
	CuAssertIntEquals (test, false, ecdh_hw_fail_pct);

	ecdh_testing_release_dependencies (test, &ecdh);
}
#endif
#endif

static void ecdh_test_ecc_hw_pairwise_consistency_test_null (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_ecc_hw_pairwise_consistency_test (NULL, ECC_PRIVKEY2, ECC_KEY_LENGTH_256,
		&ECC_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, NULL, ECC_KEY_LENGTH_256,
		&ECC_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC_PRIVKEY2,
		ECC_KEY_LENGTH_256, NULL);
	CuAssertIntEquals (test, ECDH_INVALID_ARGUMENT, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_pairwise_consistency_test_unsupported_key_length (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC_PRIVKEY2,
		ECC_KEY_LENGTH_256 - 1, &ECC_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECDH_UNSUPPORTED_KEY_LENGTH, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_pairwise_consistency_test_priv_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw,
		ECC_HW_ECDH_COMPUTE_FAILED, MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN),
		MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC_PRIVKEY2,
		ECC_KEY_LENGTH_256, &ECC_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECC_HW_ECDH_COMPUTE_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_pairwise_consistency_test_pub_error (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;

	TEST_START;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw,
		ECC_HW_ECDH_COMPUTE_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC_PRIVKEY2,
		ECC_KEY_LENGTH_256, &ECC_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECC_HW_ECDH_COMPUTE_FAILED, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}

static void ecdh_test_ecc_hw_pairwise_consistency_test_data_mismatch (CuTest *test)
{
	struct ecdh_testing ecdh;
	int status;
	uint8_t bad_pct[ECC_KEY_LENGTH_256];

	TEST_START;

	memcpy (bad_pct, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET, ECC_KEY_LENGTH_256);
	bad_pct[6] ^= 0x55;

	ecdh_testing_init_dependencies (test, &ecdh);

	status = mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY2, ECC_PRIVKEY2_LEN), MOCK_ARG (ECC_PRIVKEY2_LEN),
		MOCK_ARG_PTR_CONTAINS (&ECC_KAT_VECTORS_P256_ECC_PUBLIC,
		sizeof (ECC_KAT_VECTORS_P256_ECC_PUBLIC)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, ECC_KAT_VECTORS_P256_ECDH_SHARED_SECRET,
		ECC_KEY_LENGTH_256, 4);

	status |= mock_expect (&ecdh.ecc_hw.mock, ecdh.ecc_hw.base.ecdh_compute, &ecdh.ecc_hw, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PRIVATE, ECC_KEY_LENGTH_256),
		MOCK_ARG (ECC_KEY_LENGTH_256),
		MOCK_ARG_PTR_CONTAINS (&ECC_PUBKEY2_POINT, sizeof (ECC_PUBKEY2_POINT)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_KEY_LENGTH_256));
	status |= mock_expect_output (&ecdh.ecc_hw.mock, 3, bad_pct, ECC_KEY_LENGTH_256, 4);

	CuAssertIntEquals (test, 0, status);

	status = ecdh_ecc_hw_pairwise_consistency_test (&ecdh.ecc_hw.base, ECC_PRIVKEY2,
		ECC_KEY_LENGTH_256, &ECC_PUBKEY2_POINT);
	CuAssertIntEquals (test, ECDH_PCT_FAILURE, status);

	ecdh_testing_release_dependencies (test, &ecdh);
}


// *INDENT-OFF*
TEST_SUITE_START (ecdh);

TEST (ecdh_test_generate_random_key_p256);
TEST (ecdh_test_generate_random_key_mock_p256);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_generate_random_key_p256_cmvp_pct_fault);
#endif
TEST (ecdh_test_generate_random_key_p384);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (ecdh_test_generate_random_key_mock_p384);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_generate_random_key_p384_cmvp_pct_fault);
#endif
#endif
TEST (ecdh_test_generate_random_key_p521);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (ecdh_test_generate_random_key_mock_p521);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_generate_random_key_p521_cmvp_pct_fault);
#endif
#endif
TEST (ecdh_test_generate_random_key_no_public_key);
TEST (ecdh_test_generate_random_key_null);
TEST (ecdh_test_generate_random_key_generate_error);
TEST (ecdh_test_generate_random_key_pct_key_length_error);
TEST (ecdh_test_generate_random_key_pct_init_error);
TEST (ecdh_test_generate_random_key_pct_priv_error);
TEST (ecdh_test_generate_random_key_pct_pub_error);
TEST (ecdh_test_generate_random_key_pct_data_mismatch);
TEST (ecdh_test_generate_random_key_pct_length_mismatch);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_generate_random_key_cmvp_pct_fault_init_error);
#endif
TEST (ecdh_test_ecc_hw_generate_random_key_p256);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_ecc_hw_generate_random_key_p256_cmvp_pct_fault);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (ecdh_test_ecc_hw_generate_random_key_p384);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_ecc_hw_generate_random_key_p384_cmvp_pct_fault);
#endif
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (ecdh_test_ecc_hw_generate_random_key_p521);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_ecc_hw_generate_random_key_p521_cmvp_pct_fault);
#endif
#endif
TEST (ecdh_test_ecc_hw_generate_random_key_no_public_key);
TEST (ecdh_test_ecc_hw_generate_random_key_null);
TEST (ecdh_test_ecc_hw_generate_random_key_generate_error);
TEST (ecdh_test_ecc_hw_generate_random_key_pct_priv_error);
TEST (ecdh_test_ecc_hw_generate_random_key_pct_pub_error);
TEST (ecdh_test_ecc_hw_generate_random_key_pct_data_mismatch);
TEST (ecdh_test_pairwise_consistency_test_p256);
TEST (ecdh_test_pairwise_consistency_test_mock_p256);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_pairwise_consistency_test_p256_cmvp_pct_fault);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (ecdh_test_pairwise_consistency_test_p384);
TEST (ecdh_test_pairwise_consistency_test_mock_p384);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_pairwise_consistency_test_p384_cmvp_pct_fault);
#endif
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (ecdh_test_pairwise_consistency_test_p521);
TEST (ecdh_test_pairwise_consistency_test_mock_p521);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_pairwise_consistency_test_p521_cmvp_pct_fault);
#endif
#endif
TEST (ecdh_test_pairwise_consistency_test_null);
TEST (ecdh_test_pairwise_consistency_test_key_length_error);
TEST (ecdh_test_pairwise_consistency_test_init_error);
TEST (ecdh_test_pairwise_consistency_test_priv_error);
TEST (ecdh_test_pairwise_consistency_test_pub_error);
TEST (ecdh_test_pairwise_consistency_test_data_mismatch);
TEST (ecdh_test_pairwise_consistency_test_length_mismatch);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_pairwise_consistency_test_cmvp_pct_fault_init_error);
#endif
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_p256);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_p256_cmvp_pct_fault);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_p384);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_p384_cmvp_pct_fault);
#endif
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_p521);
#ifdef ECDH_ENABLE_FIPS_CMVP_TESTING
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_p521_cmvp_pct_fault);
#endif
#endif
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_null);
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_unsupported_key_length);
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_priv_error);
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_pub_error);
TEST (ecdh_test_ecc_hw_pairwise_consistency_test_data_mismatch);

TEST_SUITE_END;
// *INDENT-ON*
