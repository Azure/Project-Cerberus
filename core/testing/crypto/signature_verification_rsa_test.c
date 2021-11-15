// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/signature_verification_rsa.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"


TEST_SUITE_LABEL ("signature_verification_rsa");


/*******************
 * Test cases
 *******************/

static void signature_verification_rsa_test_init (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_init_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (NULL, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_rsa_init (&verification, NULL, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_rsa_init (&verification, &rsa.base, NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_release_null (CuTest *test)
{
	TEST_START;

	signature_verification_rsa_release (NULL);
}

static void signature_verification_rsa_test_verify_signature (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_verify_signature_bad_hash (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_NOPE, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_verify_signature_bad_signature (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_verify_signature_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (NULL, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, NULL, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, 0,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		NULL, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, 0);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}


TEST_SUITE_START (signature_verification_rsa);

TEST (signature_verification_rsa_test_init);
TEST (signature_verification_rsa_test_init_null);
TEST (signature_verification_rsa_test_release_null);
TEST (signature_verification_rsa_test_verify_signature);
TEST (signature_verification_rsa_test_verify_signature_bad_hash);
TEST (signature_verification_rsa_test_verify_signature_bad_signature);
TEST (signature_verification_rsa_test_verify_signature_null);

TEST_SUITE_END;
