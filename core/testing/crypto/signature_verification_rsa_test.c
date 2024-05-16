// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/signature_verification_rsa.h"
#include "crypto/signature_verification_rsa_static.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"
#include "testing/engines/rsa_testing_engine.h"


TEST_SUITE_LABEL ("signature_verification_rsa");


/*******************
 * Test cases
 *******************/

static void signature_verification_rsa_test_init_api (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init_api (&verification, &state, &rsa.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_init_api_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init_api (NULL, &state, &rsa.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_rsa_init_api (&verification, NULL, &rsa.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_rsa_init_api (&verification, &state, NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_init (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_init_no_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_init_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (NULL, &state, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_rsa_init (&verification, NULL, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_rsa_init (&verification, &state, NULL, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_static_init (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification = signature_verification_rsa_static_init (&state,
		&rsa.base);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init_state (&verification, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_static_init_no_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification = signature_verification_rsa_static_init (&state,
		&rsa.base);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init_state (&verification, NULL);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_static_init_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification = signature_verification_rsa_static_init (&state,
		&rsa.base);
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init_state (NULL, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	verification.state = NULL;
	status = signature_verification_rsa_init_state (&verification, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	verification.state = &state;
	verification.rsa = NULL;
	status = signature_verification_rsa_init_state (&verification, &RSA_PUBLIC_KEY);
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
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, &RSA_PUBLIC_KEY);
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
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_NOPE, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_verify_signature_bad_signature (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_verify_signature_static_init (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification = signature_verification_rsa_static_init (&state,
		&rsa.base);
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init_state (&verification, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_verify_signature_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, &RSA_PUBLIC_KEY);
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

static void signature_verification_rsa_test_verify_signature_no_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_set_verification_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_set_verification_key_clear_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_set_verification_key_clear_key_no_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_set_verification_key_change_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, &RSA_PUBLIC_KEY);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base,
		(uint8_t*) &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE2_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_set_verification_key_static_init (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification = signature_verification_rsa_static_init (&state,
		&rsa.base);
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init_state (&verification, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_set_verification_key_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (NULL, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_set_verification_key_not_rsa_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY) - 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	status = verification.base.set_verification_key (&verification.base, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY) + 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_is_key_valid (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.is_key_valid (&verification.base, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_is_key_valid_null (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.is_key_valid (NULL, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.is_key_valid (&verification.base, NULL, sizeof (RSA_PUBLIC_KEY));
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.is_key_valid (&verification.base, (uint8_t*) &RSA_PUBLIC_KEY, 0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void signature_verification_rsa_test_is_key_valid_not_rsa_key (CuTest *test)
{
	RSA_TESTING_ENGINE rsa;
	struct signature_verification_rsa_state state;
	struct signature_verification_rsa verification;
	int status;

	TEST_START;

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&verification, &state, &rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.is_key_valid (&verification.base, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY) - 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	status = verification.base.is_key_valid (&verification.base, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY) + 1);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_rsa_release (&verification);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}


// *INDENT-OFF*
TEST_SUITE_START (signature_verification_rsa);

TEST (signature_verification_rsa_test_init_api);
TEST (signature_verification_rsa_test_init_api_null);
TEST (signature_verification_rsa_test_init);
TEST (signature_verification_rsa_test_init_no_key);
TEST (signature_verification_rsa_test_init_null);
TEST (signature_verification_rsa_test_static_init);
TEST (signature_verification_rsa_test_static_init_no_key);
TEST (signature_verification_rsa_test_static_init_null);
TEST (signature_verification_rsa_test_release_null);
TEST (signature_verification_rsa_test_verify_signature);
TEST (signature_verification_rsa_test_verify_signature_bad_hash);
TEST (signature_verification_rsa_test_verify_signature_bad_signature);
TEST (signature_verification_rsa_test_verify_signature_static_init);
TEST (signature_verification_rsa_test_verify_signature_null);
TEST (signature_verification_rsa_test_verify_signature_no_key);
TEST (signature_verification_rsa_test_set_verification_key);
TEST (signature_verification_rsa_test_set_verification_key_clear_key);
TEST (signature_verification_rsa_test_set_verification_key_clear_key_no_key);
TEST (signature_verification_rsa_test_set_verification_key_change_key);
TEST (signature_verification_rsa_test_set_verification_key_static_init);
TEST (signature_verification_rsa_test_set_verification_key_null);
TEST (signature_verification_rsa_test_set_verification_key_not_rsa_key);
TEST (signature_verification_rsa_test_is_key_valid);
TEST (signature_verification_rsa_test_is_key_valid_null);
TEST (signature_verification_rsa_test_is_key_valid_not_rsa_key);

TEST_SUITE_END;
// *INDENT-ON*
