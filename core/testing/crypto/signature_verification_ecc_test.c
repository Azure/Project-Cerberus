// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/signature_verification_ecc.h"
#include "crypto/signature_verification_ecc_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/mock/crypto/ecc_mock.h"


TEST_SUITE_LABEL ("signature_verification_ecc");


/*******************
 * Test cases
 *******************/

static void signature_verification_ecc_test_init_api (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_api (&verification, &state, &ecc.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_api_null (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_api (NULL, &state, &ecc.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_ecc_init_api (&verification, NULL, &ecc.base);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_ecc_init_api (&verification, &state, NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_private_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_no_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_null (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (NULL, &state, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_ecc_init (&verification, NULL, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_ecc_init (&verification, &state, NULL, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,	0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_not_ecc_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_init_private_key_error (CuTest *test)
{
	struct ecc_engine_mock ecc;
	struct signature_verification_ecc_state state;
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
		MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);
}

static void signature_verification_ecc_test_static_init (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (&verification, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_static_init_private_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (&verification, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_static_init_no_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (&verification, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_static_init_null (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	verification.state = NULL;
	status = signature_verification_ecc_init_state (&verification, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	verification.state = &state;
	verification.ecc = NULL;
	status = signature_verification_ecc_init_state (&verification, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	verification.ecc = &ecc.base;
	status = signature_verification_ecc_init_state (&verification, ECC_PUBKEY_DER, 0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_static_init_not_ecc_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (&verification, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_static_init_private_key_error (CuTest *test)
{
	struct ecc_engine_mock ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, ECC_ENGINE_PUBLIC_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (&verification, ECC_PUBKEY_DER,
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
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,
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
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PRIVKEY_DER,
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
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_NOPE, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_verify_signature_bad_signature (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_NOPE, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_verify_signature_static_init (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (&verification, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_verify_signature_null (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,
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

static void signature_verification_ecc_test_verify_signature_no_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key_private_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key_clear_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key_clear_key_no_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key_change_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SHA384_TEST_HASH,
		SHA384_HASH_LENGTH, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key_static_init (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (&verification, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key_null (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PUBKEY_DER, 0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key_not_ecc_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.set_verification_key (&verification.base, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_set_verification_key_private_key_error (CuTest *test)
{
	struct ecc_engine_mock ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, ECC_ENGINE_PUBLIC_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);
}

static void signature_verification_ecc_test_is_key_valid (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.is_key_valid (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_is_key_valid_private_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.is_key_valid (&verification.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_is_key_valid_static_init (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification = signature_verification_ecc_static_init (&state,
		&ecc.base);
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init_state (&verification, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.is_key_valid (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_is_key_valid_null (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.is_key_valid (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.is_key_valid (&verification.base, NULL, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.is_key_valid (&verification.base, ECC_PUBKEY_DER, 0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_is_key_valid_not_ecc_key (CuTest *test)
{
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = verification.base.is_key_valid (&verification.base, RSA_PUBKEY_DER,
		RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_ecc_release (&verification);

	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void signature_verification_ecc_test_is_key_valid_private_key_error (CuTest *test)
{
	struct ecc_engine_mock ecc;
	struct signature_verification_ecc_state state;
	struct signature_verification_ecc verification;
	int status;

	TEST_START;

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&verification, &state, &ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = mock_expect (&ecc.mock, ecc.base.init_public_key, &ecc, ECC_ENGINE_PUBLIC_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_NOT_NULL);
	status |= mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN),
		MOCK_ARG_PTR (NULL), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = verification.base.is_key_valid (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&verification);
}


// *INDENT-OFF*
TEST_SUITE_START (signature_verification_ecc);

TEST (signature_verification_ecc_test_init_api);
TEST (signature_verification_ecc_test_init_api_null);
TEST (signature_verification_ecc_test_init);
TEST (signature_verification_ecc_test_init_private_key);
TEST (signature_verification_ecc_test_init_no_key);
TEST (signature_verification_ecc_test_init_null);
TEST (signature_verification_ecc_test_init_not_ecc_key);
TEST (signature_verification_ecc_test_init_private_key_error);
TEST (signature_verification_ecc_test_static_init);
TEST (signature_verification_ecc_test_static_init_private_key);
TEST (signature_verification_ecc_test_static_init_no_key);
TEST (signature_verification_ecc_test_static_init_null);
TEST (signature_verification_ecc_test_static_init_not_ecc_key);
TEST (signature_verification_ecc_test_static_init_private_key_error);
TEST (signature_verification_ecc_test_release_null);
TEST (signature_verification_ecc_test_verify_signature);
TEST (signature_verification_ecc_test_verify_signature_private_key);
TEST (signature_verification_ecc_test_verify_signature_bad_hash);
TEST (signature_verification_ecc_test_verify_signature_bad_signature);
TEST (signature_verification_ecc_test_verify_signature_static_init);
TEST (signature_verification_ecc_test_verify_signature_null);
TEST (signature_verification_ecc_test_verify_signature_no_key);
TEST (signature_verification_ecc_test_set_verification_key);
TEST (signature_verification_ecc_test_set_verification_key_private_key);
TEST (signature_verification_ecc_test_set_verification_key_clear_key);
TEST (signature_verification_ecc_test_set_verification_key_clear_key_no_key);
TEST (signature_verification_ecc_test_set_verification_key_change_key);
TEST (signature_verification_ecc_test_set_verification_key_static_init);
TEST (signature_verification_ecc_test_set_verification_key_null);
TEST (signature_verification_ecc_test_set_verification_key_not_ecc_key);
TEST (signature_verification_ecc_test_set_verification_key_private_key_error);
TEST (signature_verification_ecc_test_is_key_valid);
TEST (signature_verification_ecc_test_is_key_valid_private_key);
TEST (signature_verification_ecc_test_is_key_valid_static_init);
TEST (signature_verification_ecc_test_is_key_valid_null);
TEST (signature_verification_ecc_test_is_key_valid_not_ecc_key);
TEST (signature_verification_ecc_test_is_key_valid_private_key_error);

TEST_SUITE_END;
// *INDENT-ON*
