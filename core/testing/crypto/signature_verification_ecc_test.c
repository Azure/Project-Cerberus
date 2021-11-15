// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/signature_verification_ecc.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/signature_testing.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("signature_verification_ecc");


/*******************
 * Test cases
 *******************/

static void signature_verification_ecc_test_init (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_private_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_null (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (NULL, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_ecc_init (&verification, NULL, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, NULL,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PUBKEY_DER,
		0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_not_ecc_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_NOT_EC_KEY, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_private_key_error (CuTest *test)
{
	struct ecc_engine_mock ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, ECC_ENGINE_PUBLIC_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG (NULL), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void signature_verification_ecc_test_release_null (CuTest *test)
{
	TEST_START;

	signature_verification_ecc_release (NULL);
}

static void signature_verification_ecc_test_verify_signature (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_verify_signature_private_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_verify_signature_bad_hash (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_NOPE, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_verify_signature_bad_signature (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_NOPE, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_verify_signature_null (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (NULL, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, NULL, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, 0,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		NULL, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, 0);
	CuAssertIntEquals (test, ECC_ENGINE_INVALID_ARGUMENT, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}


TEST_SUITE_START (signature_verification_ecc);

TEST (signature_verification_ecc_test_init);
TEST (signature_verification_ecc_test_init_private_key);
TEST (signature_verification_ecc_test_init_null);
TEST (signature_verification_ecc_test_init_not_ecc_key);
TEST (signature_verification_ecc_test_init_private_key_error);
TEST (signature_verification_ecc_test_release_null);
TEST (signature_verification_ecc_test_verify_signature);
TEST (signature_verification_ecc_test_verify_signature_private_key);
TEST (signature_verification_ecc_test_verify_signature_bad_hash);
TEST (signature_verification_ecc_test_verify_signature_bad_signature);
TEST (signature_verification_ecc_test_verify_signature_null);

TEST_SUITE_END;
