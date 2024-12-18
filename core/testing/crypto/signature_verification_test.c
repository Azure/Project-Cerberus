// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "crypto/signature_verification_ecc.h"
#include "crypto/signature_verification_rsa.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/hash_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"


TEST_SUITE_LABEL ("signature_verification");


/**
 * Test dependencies for signature verification.
 */
struct signature_verification_testing {
	ECC_TESTING_ENGINE (ecc);								/**< ECC engine for test. */
	RSA_TESTING_ENGINE (rsa);								/**< RSA engine for test. */
	HASH_TESTING_ENGINE (hash);								/**< Hash engine for test. */
	struct hash_engine_mock hash_mock;						/**< Mock for the hash engine. */
	struct signature_verification_ecc_state ecdsa_state;	/**< Variable context for ECDSA. */
	struct signature_verification_ecc ecdsa;				/**< Verification context for ECDSA signatures. */
	struct signature_verification_rsa_state rsassa_state;	/**< Variable context for RSASSA. */
	struct signature_verification_rsa rsassa;				/**< Verification context for RSASSA signatures. */
	struct signature_verification_mock verify_mock;			/**< Mock for signature verification. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param sig_verify Testing dependencies to initialize.
 */
static void signature_verification_testing_init_dependencies (CuTest *test,
	struct signature_verification_testing *sig_verify)
{
	int status;

	status = ECC_TESTING_ENGINE_INIT (&sig_verify->ecc);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&sig_verify->rsa);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&sig_verify->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&sig_verify->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_ecc_init (&sig_verify->ecdsa, &sig_verify->ecdsa_state,
		&sig_verify->ecc.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_rsa_init (&sig_verify->rsassa, &sig_verify->rsassa_state,
		&sig_verify->rsa.base, NULL);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&sig_verify->verify_mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to release all testing dependencies.
 *
 * @param test The test framework.
 * @param sig_verify Testing dependencies to release.
 */
static void signature_verification_testing_release_dependencies (CuTest *test,
	struct signature_verification_testing *sig_verify)
{
	int status;

	status = hash_mock_validate_and_release (&sig_verify->hash_mock);
	status |= signature_verification_mock_validate_and_release (&sig_verify->verify_mock);

	CuAssertIntEquals (test, 0, status);

	signature_verification_ecc_release (&sig_verify->ecdsa);
	signature_verification_rsa_release (&sig_verify->rsassa);
	ECC_TESTING_ENGINE_RELEASE (&sig_verify->ecc);
	RSA_TESTING_ENGINE_RELEASE (&sig_verify->rsa);
	HASH_TESTING_ENGINE_RELEASE (&sig_verify->hash);
}


/*******************
 * Test cases
 *******************/

static void signature_verification_test_verify_message_ecdsa_p256_sha256 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	/* Load the verification context with the wrong key to ensure the right key gets loaded. */
	status = sig_verify.ecdsa.base.set_verification_key (&sig_verify.ecdsa.base, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_ecdsa_p256_sha256_bad_signature (
	CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_rsassa_2k_sha256 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	/* Load the verification context with the wrong key to ensure the right key gets loaded. */
	status = sig_verify.rsassa.base.set_verification_key (&sig_verify.rsassa.base,
		(uint8_t*) &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_message (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SIGNATURE_TEST2, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, 0, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_rsassa_2k_sha256_bad_signature (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SIGNATURE_BAD, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_rsassa_2k_sha384 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA384, (uint8_t*) message, strlen (message), (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SHA384_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_rsassa_2k_sha384_bad_signature (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA384, (uint8_t*) message, strlen (message), (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SHA384_SIGNATURE_BAD, RSA_KEY_LENGTH_2K);
#ifdef HASH_ENABLE_SHA384
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_rsassa_2k_sha512 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA512, (uint8_t*) message, strlen (message), (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SHA512_SIGNATURE_TEST2, RSA_KEY_LENGTH_2K);
#ifdef HASH_ENABLE_SHA512
	CuAssertIntEquals (test, 0, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_rsassa_2k_sha512_bad_signature (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA512, (uint8_t*) message, strlen (message), (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SHA512_SIGNATURE_BAD, RSA_KEY_LENGTH_2K);
#ifdef HASH_ENABLE_SHA512
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);
#else
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);
#endif

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_no_public_key (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Nope";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	/* Pre-load the correct key into the verification context. */
	status = sig_verify.ecdsa.base.set_verification_key (&sig_verify.ecdsa.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), NULL, 0, ECC_SIGNATURE_NOPE,
		ECC_SIG_NOPE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* The verification context should be unmodified. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_null (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (NULL, &sig_verify.hash.base, HASH_TYPE_SHA256,
		(uint8_t*) message, strlen (message), ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, NULL, HASH_TYPE_SHA256,
		(uint8_t*) message, strlen (message), ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, NULL, strlen (message), ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		NULL, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, 0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_inconsistent_key (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), NULL, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INCONSISTENT_KEY, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), ECC_PUBKEY_DER, 0,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INCONSISTENT_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_unknown_hash_algorithm (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_INVALID, (uint8_t*) message, strlen (message), ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_hash_start_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.start_sha256,
		&sig_verify.hash_mock, HASH_ENGINE_START_SHA256_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base,
		&sig_verify.hash_mock.base, HASH_TYPE_SHA256, (uint8_t*) message, strlen (message),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_hash_update_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.start_sha256,
		&sig_verify.hash_mock, 0);

	status |= mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.update,
		&sig_verify.hash_mock, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (message, strlen (message)), MOCK_ARG (strlen (message)));

	status |= mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.cancel,
		&sig_verify.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base,
		&sig_verify.hash_mock.base, HASH_TYPE_SHA256, (uint8_t*) message, strlen (message),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_hash_finish_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.start_sha256,
		&sig_verify.hash_mock, 0);

	status |= mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.update,
		&sig_verify.hash_mock, 0, MOCK_ARG_PTR_CONTAINS (message, strlen (message)),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.finish,
		&sig_verify.hash_mock, HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.cancel,
		&sig_verify.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_message (&sig_verify.ecdsa.base,
		&sig_verify.hash_mock.base, HASH_TYPE_SHA256, (uint8_t*) message, strlen (message),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_set_key_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = mock_expect (&sig_verify.verify_mock.mock,
		sig_verify.verify_mock.base.set_verification_key, &sig_verify.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_message (&sig_verify.verify_mock.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, (uint8_t*) message, strlen (message),
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_message_verify_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = mock_expect (&sig_verify.verify_mock.mock,
		sig_verify.verify_mock.base.verify_signature, &sig_verify.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN), MOCK_ARG (ECC_SIG_TEST_LEN));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_message (&sig_verify.verify_mock.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, (uint8_t*) message, strlen (message), NULL, 0,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_ecdsa_p256_sha256 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	/* Load the verification context with the wrong key to ensure the right key gets loaded. */
	status = sig_verify.ecdsa.base.set_verification_key (&sig_verify.ecdsa.base, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should still be active. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.finish (&sig_verify.hash.base, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_ecdsa_p256_sha256_bad_signature (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* The hash context should still be active. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.finish (&sig_verify.hash.base, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_rsassa_2k_sha256 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	/* Load the verification context with the wrong key to ensure the right key gets loaded. */
	status = sig_verify.rsassa.base.set_verification_key (&sig_verify.rsassa.base,
		(uint8_t*) &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY), RSA_SIGNATURE_TEST,
		RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should still be active. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.finish (&sig_verify.hash.base, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_rsassa_2k_sha256_bad_signature (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, (uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY), RSA_SIGNATURE_BAD,
		RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* The hash context should still be active. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.finish (&sig_verify.hash.base, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

#ifdef HASH_ENABLE_SHA384
static void signature_verification_test_verify_hash_rsassa_2k_sha384 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha384 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA384, (uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY),
		RSA_SHA384_SIGNATURE_TEST2, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, 0, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_rsassa_2k_sha384_bad_signature (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha384 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA384, (uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY),
		RSA_SHA384_SIGNATURE_BAD, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void signature_verification_test_verify_hash_rsassa_2k_sha512 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha512 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA512, (uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY),
		RSA_SHA512_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, 0, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_rsassa_2k_sha512_bad_signature (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha512 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.rsassa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA512, (uint8_t*) &RSA_PUBLIC_KEY, sizeof (RSA_PUBLIC_KEY),
		RSA_SHA512_SIGNATURE_BAD, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}
#endif

static void signature_verification_test_verify_hash_no_public_key (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Nope";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	/* Pre-load the correct key into the verification context. */
	status = sig_verify.ecdsa.base.set_verification_key (&sig_verify.ecdsa.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, NULL, 0, ECC_SIGNATURE_NOPE, ECC_SIG_NOPE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* The verification context should be unmodified. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_null (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_hash (NULL, &sig_verify.hash.base, HASH_TYPE_SHA256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, NULL, HASH_TYPE_SHA256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, NULL, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, 0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_inconsistent_key (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, NULL, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INCONSISTENT_KEY, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_SHA256, ECC_PUBKEY_DER, 0, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INCONSISTENT_KEY, status);

	/* The hash context should still be active. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.finish (&sig_verify.hash.base, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_unknown_hash_algorithm (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash.base,
		HASH_TYPE_INVALID, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST,
		ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	/* The hash context should still be active. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.finish (&sig_verify.hash.base, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_get_hash_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.get_hash,
		&sig_verify.hash_mock, HASH_ENGINE_GET_HASH_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.ecdsa.base, &sig_verify.hash_mock.base,
		HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_GET_HASH_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_set_key_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&sig_verify.verify_mock.mock,
		sig_verify.verify_mock.base.set_verification_key, &sig_verify.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.verify_mock.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_verify_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&sig_verify.verify_mock.mock,
		sig_verify.verify_mock.base.verify_signature, &sig_verify.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN), MOCK_ARG (ECC_SIG_TEST_LEN));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash (&sig_verify.verify_mock.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, NULL, 0, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_ecdsa_p256_sha256 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	/* Load the verification context with the wrong key to ensure the right key gets loaded. */
	status = sig_verify.ecdsa.base.set_verification_key (&sig_verify.ecdsa.base, ECC_PUBKEY2_DER,
		ECC_PUBKEY2_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_ecdsa_p256_sha256_bad_signature (
	CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_rsassa_2k_sha256 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	/* Load the verification context with the wrong key to ensure the right key gets loaded. */
	status = sig_verify.rsassa.base.set_verification_key (&sig_verify.rsassa.base,
		(uint8_t*) &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.rsassa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SIGNATURE_TEST2, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_rsassa_2k_sha256_bad_signature (
	CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	/* Load the verification context with the wrong key to ensure the right key gets loaded. */
	status = sig_verify.rsassa.base.set_verification_key (&sig_verify.rsassa.base,
		(uint8_t*) &RSA_PUBLIC_KEY2, sizeof (RSA_PUBLIC_KEY2));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.rsassa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SIGNATURE_BAD, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

#ifdef HASH_ENABLE_SHA384
static void signature_verification_test_verify_hash_and_finish_rsassa_2k_sha384 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha384 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.rsassa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA384, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SHA384_SIGNATURE_TEST2, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_rsassa_2k_sha384_bad_signature (
	CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test2";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha384 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.rsassa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA384, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SHA384_SIGNATURE_BAD, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void signature_verification_test_verify_hash_and_finish_rsassa_2k_sha512 (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha512 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.rsassa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA512, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SHA512_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_rsassa_2k_sha512_bad_signature (
	CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha512 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.rsassa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA512, (uint8_t*) &RSA_PUBLIC_KEY,
		sizeof (RSA_PUBLIC_KEY), RSA_SHA512_SIGNATURE_BAD, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_BAD_SIGNATURE, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* There should be no active key left in the verification context. */
	status = sig_verify.rsassa.base.verify_signature (&sig_verify.rsassa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, RSA_SIGNATURE_TEST, RSA_KEY_LENGTH_2K);
	CuAssertIntEquals (test, SIG_VERIFICATION_NO_KEY, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}
#endif

static void signature_verification_test_verify_hash_and_finish_no_public_key (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Nope";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	/* Pre-load the correct key into the verification context. */
	status = sig_verify.ecdsa.base.set_verification_key (&sig_verify.ecdsa.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, NULL, 0, ECC_SIGNATURE_NOPE, ECC_SIG_NOPE_LEN);
	CuAssertIntEquals (test, 0, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* The verification context should be unmodified. */
	status = sig_verify.ecdsa.base.verify_signature (&sig_verify.ecdsa.base, SHA256_TEST_HASH,
		SHA256_HASH_LENGTH, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_null (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	/* NULL Verification */
	status = mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.cancel,
		&sig_verify.hash_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (NULL, &sig_verify.hash_mock.base,
		HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = mock_validate (&sig_verify.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* NULL Signature */
	status = mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.cancel,
		&sig_verify.hash_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash_mock.base, HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, NULL,
		ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = mock_validate (&sig_verify.hash_mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* 0 Signature Length */
	status = mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.cancel,
		&sig_verify.hash_mock, 0);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash_mock.base, HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, 0);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_null_hash (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base, NULL,
		HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_inconsistent_key (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	/* NULL Key, Valid Length */
	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, NULL, ECC_PUBKEY_DER_LEN, ECC_SIGNATURE_TEST,
		ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INCONSISTENT_KEY, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	/* Valid Key, Zero Length */
	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, ECC_PUBKEY_DER, 0, ECC_SIGNATURE_TEST,
		ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INCONSISTENT_KEY, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_unknown_hash_algorithm (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);
	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash.base, HASH_TYPE_INVALID, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_hash_finish_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.finish,
		&sig_verify.hash_mock, HASH_ENGINE_FINISH_FAILED, MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));

	status |= mock_expect (&sig_verify.hash_mock.mock, sig_verify.hash_mock.base.cancel,
		&sig_verify.hash_mock, 0);

	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.ecdsa.base,
		&sig_verify.hash_mock.base, HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_set_key_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&sig_verify.verify_mock.mock,
		sig_verify.verify_mock.base.set_verification_key, &sig_verify.verify_mock,
		SIG_VERIFICATION_SET_KEY_FAILED, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.verify_mock.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}

static void signature_verification_test_verify_hash_and_finish_verify_error (CuTest *test)
{
	struct signature_verification_testing sig_verify;
	const char *message = "Test";
	int status;

	TEST_START;

	signature_verification_testing_init_dependencies (test, &sig_verify);

	status = sig_verify.hash.base.start_sha256 (&sig_verify.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&sig_verify.verify_mock.mock,
		sig_verify.verify_mock.base.verify_signature, &sig_verify.verify_mock,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA256_TEST_HASH, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN), MOCK_ARG (ECC_SIG_TEST_LEN));
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_verify_hash_and_finish (&sig_verify.verify_mock.base,
		&sig_verify.hash.base, HASH_TYPE_SHA256, NULL, 0, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	/* The hash context should be closed. */
	status = sig_verify.hash.base.update (&sig_verify.hash.base, (uint8_t*) message,
		strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	signature_verification_testing_release_dependencies (test, &sig_verify);
}


// *INDENT-OFF*
TEST_SUITE_START (signature_verification);

TEST (signature_verification_test_verify_message_ecdsa_p256_sha256);
TEST (signature_verification_test_verify_message_ecdsa_p256_sha256_bad_signature);
TEST (signature_verification_test_verify_message_rsassa_2k_sha256);
TEST (signature_verification_test_verify_message_rsassa_2k_sha256_bad_signature);
TEST (signature_verification_test_verify_message_rsassa_2k_sha384);
TEST (signature_verification_test_verify_message_rsassa_2k_sha384_bad_signature);
TEST (signature_verification_test_verify_message_rsassa_2k_sha512);
TEST (signature_verification_test_verify_message_rsassa_2k_sha512_bad_signature);
TEST (signature_verification_test_verify_message_no_public_key);
TEST (signature_verification_test_verify_message_null);
TEST (signature_verification_test_verify_message_inconsistent_key);
TEST (signature_verification_test_verify_message_unknown_hash_algorithm);
TEST (signature_verification_test_verify_message_hash_start_error);
TEST (signature_verification_test_verify_message_hash_update_error);
TEST (signature_verification_test_verify_message_hash_finish_error);
TEST (signature_verification_test_verify_message_set_key_error);
TEST (signature_verification_test_verify_message_verify_error);
TEST (signature_verification_test_verify_hash_ecdsa_p256_sha256);
TEST (signature_verification_test_verify_hash_ecdsa_p256_sha256_bad_signature);
TEST (signature_verification_test_verify_hash_rsassa_2k_sha256);
TEST (signature_verification_test_verify_hash_rsassa_2k_sha256_bad_signature);
#ifdef HASH_ENABLE_SHA384
TEST (signature_verification_test_verify_hash_rsassa_2k_sha384);
TEST (signature_verification_test_verify_hash_rsassa_2k_sha384_bad_signature);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (signature_verification_test_verify_hash_rsassa_2k_sha512);
TEST (signature_verification_test_verify_hash_rsassa_2k_sha512_bad_signature);
#endif
TEST (signature_verification_test_verify_hash_no_public_key);
TEST (signature_verification_test_verify_hash_null);
TEST (signature_verification_test_verify_hash_inconsistent_key);
TEST (signature_verification_test_verify_hash_unknown_hash_algorithm);
TEST (signature_verification_test_verify_hash_get_hash_error);
TEST (signature_verification_test_verify_hash_set_key_error);
TEST (signature_verification_test_verify_hash_verify_error);
TEST (signature_verification_test_verify_hash_and_finish_ecdsa_p256_sha256);
TEST (signature_verification_test_verify_hash_and_finish_ecdsa_p256_sha256_bad_signature);
TEST (signature_verification_test_verify_hash_and_finish_rsassa_2k_sha256);
TEST (signature_verification_test_verify_hash_and_finish_rsassa_2k_sha256_bad_signature);
#ifdef HASH_ENABLE_SHA384
TEST (signature_verification_test_verify_hash_and_finish_rsassa_2k_sha384);
TEST (signature_verification_test_verify_hash_and_finish_rsassa_2k_sha384_bad_signature);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (signature_verification_test_verify_hash_and_finish_rsassa_2k_sha512);
TEST (signature_verification_test_verify_hash_and_finish_rsassa_2k_sha512_bad_signature);
#endif
TEST (signature_verification_test_verify_hash_and_finish_no_public_key);
TEST (signature_verification_test_verify_hash_and_finish_null);
TEST (signature_verification_test_verify_hash_and_finish_null_hash);
TEST (signature_verification_test_verify_hash_and_finish_inconsistent_key);
TEST (signature_verification_test_verify_hash_and_finish_unknown_hash_algorithm);
TEST (signature_verification_test_verify_hash_and_finish_hash_finish_error);
TEST (signature_verification_test_verify_hash_and_finish_set_key_error);
TEST (signature_verification_test_verify_hash_and_finish_verify_error);

TEST_SUITE_END;
// *INDENT-ON*
