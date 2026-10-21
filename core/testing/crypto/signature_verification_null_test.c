// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "crypto/signature_verification_null.h"
#include "crypto/signature_verification_null_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"

TEST_SUITE_LABEL ("signature_verification_null");


/*******************
 * Test cases
 *******************/

static void signature_verification_null_test_init (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.get_max_signature_length);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = signature_verification_null_init (NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);
}

static void signature_verification_null_test_static_init (CuTest *test)
{
	struct signature_verification_null verification =
		signature_verification_null_static_init ();

	TEST_START;

	CuAssertPtrNotNull (test, verification.base.verify_signature);
	CuAssertPtrNotNull (test, verification.base.get_max_signature_length);
	CuAssertPtrNotNull (test, verification.base.set_verification_key);
	CuAssertPtrNotNull (test, verification.base.is_key_valid);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_release_null (CuTest *test)
{
	TEST_START;

	signature_verification_null_release (NULL);
}

static void signature_verification_null_test_verify_signature (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
static void signature_verification_null_test_verify_signature_sha384 (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SHA384_TEST_HASH,
		SHA384_HASH_LENGTH, ECC384_SIGNATURE_TEST, ECC384_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}
#endif

static void signature_verification_null_test_verify_signature_bad_hash (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_NOPE, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_verify_signature_bad_signature (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_NOPE, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_verify_signature_static_init (CuTest *test)
{
	struct signature_verification_null verification =
		signature_verification_null_static_init ();
	int status;

	TEST_START;

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_verify_signature_null (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (NULL, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, NULL, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, 0,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		NULL, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, 0);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_verify_signature_no_key (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_get_max_signature_length (CuTest *test)
{
	struct signature_verification_null verification;
	int status;
	size_t max_length;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.get_max_signature_length (&verification.base, &max_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_MAX_KEY_LENGTH, max_length);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_get_max_signature_length_no_key (CuTest *test)
{
	struct signature_verification_null verification;
	int status;
	size_t max_length;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.get_max_signature_length (&verification.base, &max_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_MAX_KEY_LENGTH, max_length);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_get_max_signature_length_static_init (CuTest *test)
{
	struct signature_verification_null verification =
		signature_verification_null_static_init ();
	int status;
	size_t max_length;

	TEST_START;

	status = verification.base.get_max_signature_length (&verification.base, &max_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA_MAX_KEY_LENGTH, max_length);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_get_max_signature_length_null (CuTest *test)
{
	struct signature_verification_null verification;
	int status;
	size_t max_length;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.get_max_signature_length (NULL, &max_length);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.get_max_signature_length (&verification.base, NULL);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_set_verification_key (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_set_verification_key_private_key (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_set_verification_key_clear_key (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_set_verification_key_change_key (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
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

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_set_verification_key_static_init (CuTest *test)
{
	struct signature_verification_null verification =
		signature_verification_null_static_init ();
	int status;

	TEST_START;

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_set_verification_key_null (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_set_verification_key_zero_length (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.set_verification_key (&verification.base, ECC_PUBKEY_DER, 0);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_is_key_valid (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.is_key_valid (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_is_key_valid_private_key (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.is_key_valid (&verification.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_is_key_valid_static_init (CuTest *test)
{
	struct signature_verification_null verification =
		signature_verification_null_static_init ();
	int status;

	TEST_START;

	status = verification.base.is_key_valid (&verification.base, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.verify_signature (&verification.base, SIG_HASH_TEST, SIG_HASH_LEN,
		ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

static void signature_verification_null_test_is_key_valid_null (CuTest *test)
{
	struct signature_verification_null verification;
	int status;

	TEST_START;

	status = signature_verification_null_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = verification.base.is_key_valid (NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.is_key_valid (&verification.base, NULL, ECC_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_ARGUMENT, status);

	status = verification.base.is_key_valid (&verification.base, ECC_PUBKEY_DER, 0);
	CuAssertIntEquals (test, 0, status);

	signature_verification_null_release (&verification);
}

// *INDENT-OFF*
TEST_SUITE_START (signature_verification_null);

TEST (signature_verification_null_test_init);
TEST (signature_verification_null_test_init_null);
TEST (signature_verification_null_test_static_init);
TEST (signature_verification_null_test_release_null);
TEST (signature_verification_null_test_verify_signature);
#if (defined HASH_ENABLE_SHA384) && (ECC_MAX_KEY_LENGTH >= ECC_KEY_LENGTH_384)
TEST (signature_verification_null_test_verify_signature_sha384);
#endif
TEST (signature_verification_null_test_verify_signature_bad_hash);
TEST (signature_verification_null_test_verify_signature_bad_signature);
TEST (signature_verification_null_test_verify_signature_static_init);
TEST (signature_verification_null_test_verify_signature_null);
TEST (signature_verification_null_test_verify_signature_no_key);
TEST (signature_verification_null_test_get_max_signature_length);
TEST (signature_verification_null_test_get_max_signature_length_no_key);
TEST (signature_verification_null_test_get_max_signature_length_static_init);
TEST (signature_verification_null_test_get_max_signature_length_null);
TEST (signature_verification_null_test_set_verification_key);
TEST (signature_verification_null_test_set_verification_key_private_key);
TEST (signature_verification_null_test_set_verification_key_clear_key);
TEST (signature_verification_null_test_set_verification_key_change_key);
TEST (signature_verification_null_test_set_verification_key_static_init);
TEST (signature_verification_null_test_set_verification_key_null);
TEST (signature_verification_null_test_set_verification_key_zero_length);
TEST (signature_verification_null_test_is_key_valid);
TEST (signature_verification_null_test_is_key_valid_private_key);
TEST (signature_verification_null_test_is_key_valid_static_init);
TEST (signature_verification_null_test_is_key_valid_null);

TEST_SUITE_END;
// *INDENT-ON*
