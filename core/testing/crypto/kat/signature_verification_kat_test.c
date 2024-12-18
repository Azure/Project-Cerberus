// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "crypto/ecdsa.h"
#include "crypto/kat/ecc_kat_vectors.h"
#include "crypto/kat/rsa_kat_vectors.h"
#include "crypto/kat/signature_verification_kat.h"
#include "crypto/rsassa.h"
#include "crypto/signature_verification_ecc.h"
#include "crypto/signature_verification_rsa.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"


TEST_SUITE_LABEL ("signature_verification_kat");


/*******************
 * Test cases
 *******************/

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p256_sha256 (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p256_sha256 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p256_sha256_bad_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p256_sha256 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, ECDSA_P256_VERIFY_SELF_TEST_FAILED, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p256_sha256_null (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p256_sha256 (NULL, &hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p256_sha256 (&ecdsa.base, NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p256_sha256_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p256_sha256 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p384_sha384 (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p384_sha384 (&ecdsa.base,
		&hash.base);
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECDSA_UNSUPPORTED_SELF_TEST, status);
#endif

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void signature_verification_kat_test_run_self_test_verify_ecdsa_p384_sha384_bad_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p384_sha384 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, ECDSA_P384_VERIFY_SELF_TEST_FAILED, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p384_sha384_null (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p384_sha384 (NULL, &hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p384_sha384 (&ecdsa.base, NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p384_sha384_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p384_sha384 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p521_sha512 (CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p521_sha512 (&ecdsa.base,
		&hash.base);
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, ECDSA_UNSUPPORTED_SELF_TEST, status);
#endif

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void signature_verification_kat_test_run_self_test_verify_ecdsa_p521_sha512_bad_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p521_sha512 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, ECDSA_P521_VERIFY_SELF_TEST_FAILED, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p521_sha512_null (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p521_sha512 (NULL, &hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p521_sha512 (&ecdsa.base, NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_ecdsa_p521_sha512_error (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_ecdsa_p521_sha512 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256 (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_bad_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, ECDSA_P256_VERIFY_SELF_TEST_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_null (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (NULL,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (&ecdsa.base,
		NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_hash_start_error (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_hash_update_error (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_ECDSA_SIGNED_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_verify_error
	(CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P256_SHA256_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p256_sha256 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384 (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (&ecdsa.base,
		&hash.base);
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
	CuAssertIntEquals (test, 0, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);
#else
	CuAssertIntEquals (test, ECDSA_UNSUPPORTED_SELF_TEST, status);
#endif

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_bad_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, ECDSA_P384_VERIFY_SELF_TEST_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_null (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (NULL,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (&ecdsa.base,
		NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_hash_start_error (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash,
		HASH_ENGINE_START_SHA384_FAILED);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_hash_update_error (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_ECDSA_SIGNED_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_verify_error
	(CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P384_SHA384_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p384_sha384 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512 (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (&ecdsa.base,
		&hash.base);
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
	CuAssertIntEquals (test, 0, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);
#else
	CuAssertIntEquals (test, ECDSA_UNSUPPORTED_SELF_TEST, status);
#endif

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_bad_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, ECDSA_P521_VERIFY_SELF_TEST_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_null (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (NULL,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (&ecdsa.base,
		NULL);
	CuAssertIntEquals (test, ECDSA_INVALID_ARGUMENT, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_hash_start_error (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha512, &hash,
		HASH_ENGINE_START_SHA512_FAILED);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_hash_update_error (
	CuTest *test)
{
	ECC_TESTING_ENGINE (ecc);
	struct signature_verification_ecc_state ecdsa_state;
	struct signature_verification_ecc ecdsa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&ecdsa, &ecdsa_state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha512, &hash, 0);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SIGNED, ECC_KAT_VECTORS_ECDSA_SIGNED_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_ECDSA_SIGNED_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&ecdsa);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_verify_error
	(CuTest *test)
{
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock ecdsa;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER,
		ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_ECC_PUBLIC_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.verify_signature, &ecdsa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_ECDSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER,
		ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN),
		MOCK_ARG (ECC_KAT_VECTORS_P521_SHA512_ECDSA_SIGNATURE_DER_LEN));

	status |= mock_expect (&ecdsa.mock, ecdsa.base.set_verification_key, &ecdsa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_ecdsa_p521_sha512 (&ecdsa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, ECC_KAT_VECTORS_ECDSA_SIGNED,
		ECC_KAT_VECTORS_ECDSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&ecdsa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha256 (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha256 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha256_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha256 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_2K_VERIFY_SELF_TEST_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha256_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha256 (NULL, &hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha256 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha256_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha256 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha384 (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha384 (&rsassa.base,
		&hash.base);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, RSASSA_UNSUPPORTED_SELF_TEST, status);
#endif

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA384
static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha384_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_2K_VERIFY_SELF_TEST_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha384_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha384 (NULL, &hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha384 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha384_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha512 (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha512 (&rsassa.base,
		&hash.base);
#ifdef HASH_ENABLE_SHA512
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, RSASSA_UNSUPPORTED_SELF_TEST, status);
#endif

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA512
static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha512_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha512 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_2K_VERIFY_SELF_TEST_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha512_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha512 (NULL, &hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha512 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha512_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_2048_sha512 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_rsassa_3072_sha384 (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_3072_sha384 (&rsassa.base,
		&hash.base);
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, RSASSA_UNSUPPORTED_SELF_TEST, status);
#endif

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
static void signature_verification_kat_test_run_self_test_verify_rsassa_3072_sha384_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_3072_PUBLIC, sizeof (RSA_KAT_VECTORS_3072_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_3072_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_3072_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_3K_VERIFY_SELF_TEST_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_3072_sha384_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_3072_sha384 (NULL, &hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_3072_sha384 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_3072_sha384_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_3072_PUBLIC, sizeof (RSA_KAT_VECTORS_3072_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_3072_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_3072_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_rsassa_4096_sha384 (CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_4096_sha384 (&rsassa.base,
		&hash.base);
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, RSASSA_UNSUPPORTED_SELF_TEST, status);
#endif

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
static void signature_verification_kat_test_run_self_test_verify_rsassa_4096_sha384_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_4096_PUBLIC, sizeof (RSA_KAT_VECTORS_4096_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_4096_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_4096_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_4K_VERIFY_SELF_TEST_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_4096_sha384_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_4096_sha384 (NULL, &hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_4096_sha384 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_rsassa_4096_sha384_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_4096_PUBLIC, sizeof (RSA_KAT_VECTORS_4096_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_4096_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_rsassa_4096_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256 (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_2K_VERIFY_SELF_TEST_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (NULL,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, RSASSA_INVALID_ARGUMENT, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_hash_start_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_hash_update_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_RSASSA_SIGNED_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_verify_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA256_DIGEST, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA256_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha256 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384 (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (&rsassa.base,
		&hash.base);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, RSASSA_UNSUPPORTED_SELF_TEST, status);
#endif

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA384
static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_2K_VERIFY_SELF_TEST_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (NULL,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, RSASSA_INVALID_ARGUMENT, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_hash_start_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash,
		HASH_ENGINE_START_SHA384_FAILED);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_hash_update_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_RSASSA_SIGNED_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_verify_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512 (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (&rsassa.base,
		&hash.base);
#ifdef HASH_ENABLE_SHA512
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, RSASSA_UNSUPPORTED_SELF_TEST, status);
#endif

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#ifdef HASH_ENABLE_SHA512
static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_2K_VERIFY_SELF_TEST_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (NULL,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, RSASSA_INVALID_ARGUMENT, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_hash_start_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha512, &hash,
		HASH_ENGINE_START_SHA512_FAILED);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA512_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_hash_update_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha512, &hash, 0);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_RSASSA_SIGNED_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_verify_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_2048_PUBLIC, sizeof (RSA_KAT_VECTORS_2048_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_2048_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA512_DIGEST, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_2048_SHA512_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_2048_sha512 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384 (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (&rsassa.base,
		&hash.base);
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, RSASSA_UNSUPPORTED_SELF_TEST, status);
#endif

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_3072_PUBLIC, sizeof (RSA_KAT_VECTORS_3072_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_3072_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_3K_VERIFY_SELF_TEST_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (NULL,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, RSASSA_INVALID_ARGUMENT, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_hash_start_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash,
		HASH_ENGINE_START_SHA384_FAILED);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_hash_update_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_RSASSA_SIGNED_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_verify_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_3072_PUBLIC, sizeof (RSA_KAT_VECTORS_3072_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_3072_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_3072_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_3072_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384 (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (&rsassa.base,
		&hash.base);
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, RSASSA_UNSUPPORTED_SELF_TEST, status);
#endif

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_bad_signature (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_4096_PUBLIC, sizeof (RSA_KAT_VECTORS_4096_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_4096_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, RSASSA_4K_VERIFY_SELF_TEST_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_null (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (NULL,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (&rsassa.base,
		NULL);
	CuAssertIntEquals (test, RSASSA_INVALID_ARGUMENT, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_hash_start_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash,
		HASH_ENGINE_START_SHA384_FAILED);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA384_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_hash_update_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	struct signature_verification_rsa_state rsassa_state;
	struct signature_verification_rsa rsassa;
	struct hash_engine_mock hash;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&rsassa, &rsassa_state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha384, &hash, 0);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SIGNED, RSA_KAT_VECTORS_RSASSA_SIGNED_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_RSASSA_SIGNED_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&rsassa);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void
signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_verify_error (
	CuTest *test)
{
	RSA_TESTING_ENGINE (rsa);
	HASH_TESTING_ENGINE (hash);
	struct signature_verification_mock rsassa;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&rsassa);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR_CONTAINS (&RSA_KAT_VECTORS_4096_PUBLIC, sizeof (RSA_KAT_VECTORS_4096_PUBLIC)),
		MOCK_ARG (sizeof (RSA_KAT_VECTORS_4096_PUBLIC)));

	status |= mock_expect (&rsassa.mock, rsassa.base.verify_signature, &rsassa,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_RSASSA_SHA384_DIGEST, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE,
		RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN),
		MOCK_ARG (RSA_KAT_VECTORS_4096_SHA384_RSASSA_V15_SIGNATURE_LEN));

	status |= mock_expect (&rsassa.mock, rsassa.base.set_verification_key, &rsassa, 0,
		MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_kat_run_self_test_verify_hash_rsassa_4096_sha384 (&rsassa.base,
		&hash.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should not be active. */
	status = hash.base.update (&hash.base, RSA_KAT_VECTORS_RSASSA_SIGNED,
		RSA_KAT_VECTORS_RSASSA_SIGNED_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = signature_verification_mock_validate_and_release (&rsassa);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}
#endif


// *INDENT-OFF*
TEST_SUITE_START (signature_verification_kat);

TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p256_sha256);
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p256_sha256_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p256_sha256_null);
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p256_sha256_error);
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p384_sha384);
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p384_sha384_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p384_sha384_null);
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p384_sha384_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p521_sha512);
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p521_sha512_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p521_sha512_null);
TEST (signature_verification_kat_test_run_self_test_verify_ecdsa_p521_sha512_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_null);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_hash_start_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_hash_update_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p256_sha256_verify_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384);
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_null);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_hash_start_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_hash_update_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p384_sha384_verify_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512);
#if (defined HASH_ENABLE_SHA512) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_521)
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_null);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_hash_start_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_hash_update_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_ecdsa_p521_sha512_verify_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha256);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha256_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha256_null);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha256_error);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha384);
#ifdef HASH_ENABLE_SHA384
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha384_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha384_null);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha384_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha512);
#ifdef HASH_ENABLE_SHA512
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha512_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha512_null);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_2048_sha512_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_3072_sha384);
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_3072_sha384_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_3072_sha384_null);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_3072_sha384_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_4096_sha384);
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_4096_sha384_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_4096_sha384_null);
TEST (signature_verification_kat_test_run_self_test_verify_rsassa_4096_sha384_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_null);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_hash_start_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_hash_update_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha256_verify_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384);
#ifdef HASH_ENABLE_SHA384
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_null);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_hash_start_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_hash_update_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha384_verify_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512);
#ifdef HASH_ENABLE_SHA512
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_null);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_hash_start_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_hash_update_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_2048_sha512_verify_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384);
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_3K)
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_null);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_hash_start_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_hash_update_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_3072_sha384_verify_error);
#endif
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384);
#if (defined HASH_ENABLE_SHA384) && (RSA_MAX_KEY_LENGTH >= RSA_KEY_LENGTH_4K)
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_bad_signature);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_null);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_hash_start_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_hash_update_error);
TEST (signature_verification_kat_test_run_self_test_verify_hash_rsassa_4096_sha384_verify_error);
#endif

TEST_SUITE_END;
// *INDENT-ON*
