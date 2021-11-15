// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include "testing.h"
#include "common/authorization_challenge.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/engines/rng_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"


TEST_SUITE_LABEL ("authorization_challenge");


/*******************
 * Test cases
 *******************/

static void authorization_challenge_test_init (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.base.authorize);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_init_null (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (NULL, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init (&auth, NULL, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init (&auth, &rng.base, NULL, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, NULL, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, NULL,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_init_key_error (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	struct ecc_engine_mock ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void authorization_challenge_test_init_sig_length_error (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	struct ecc_engine_mock ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	status |= mock_expect (&ecc.mock, ecc.base.get_signature_max_length, &ecc,
		ECC_ENGINE_SIG_LENGTH_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_LENGTH_FAILED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void authorization_challenge_test_init_with_tag (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, 1);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.base.authorize);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_init_with_tag_null (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init_with_tag (NULL, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_with_tag (&auth, NULL, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, NULL, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, NULL,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		NULL, ECC_PRIVKEY_DER_LEN, &verification.base, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL, 1);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_init_with_tag_key_error (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	struct ecc_engine_mock ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void authorization_challenge_test_init_with_tag_sig_length_error (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	struct ecc_engine_mock ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	status |= mock_expect (&ecc.mock, ecc.base.get_signature_max_length, &ecc,
		ECC_ENGINE_SIG_LENGTH_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));

	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_LENGTH_FAILED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void authorization_challenge_test_release_null (CuTest *test)
{
	TEST_START;

	authorization_challenge_release (NULL);
}

static void authorization_challenge_test_authorize_no_nonce (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	size_t length;
	struct ecc_public_key nonce_key;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.init_key_pair (&ecc.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&nonce_key);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	status = hash.base.calculate_sha256 (&hash.base, nonce, AUTH_CHALLENGE_NONCE_LENGTH,
		nonce_hash, sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.verify (&ecc.base, &nonce_key, nonce_hash, SHA256_HASH_LENGTH,
		&nonce[AUTH_CHALLENGE_NONCE_LENGTH], length - AUTH_CHALLENGE_NONCE_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	ecc.base.release_key_pair (&ecc.base, NULL, &nonce_key);
	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_no_nonce_with_tag (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	size_t length;
	struct ecc_public_key nonce_key;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];
	uint32_t tag = 1234;
	size_t token_len = 4 + AUTH_CHALLENGE_NONCE_LENGTH;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.init_key_pair (&ecc.base, ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, NULL,
		&nonce_key);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, tag);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, tag, *((uint32_t*) nonce));

	status = hash.base.calculate_sha256 (&hash.base, nonce, token_len, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = ecc.base.verify (&ecc.base, &nonce_key, nonce_hash, SHA256_HASH_LENGTH,
		&nonce[token_len], length - token_len);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	ecc.base.release_key_pair (&ecc.base, NULL, &nonce_key);
	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_with_signed_nonce (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_with_signed_nonce_with_tag (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[4 + AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];
	uint32_t tag = 1234;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, tag);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, tag, *((uint32_t*) nonce));

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_no_signature (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	memcpy (nonce_signed, nonce, length);
	nonce = nonce_signed;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_no_signature_with_tag (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[4 + AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint32_t tag = 1234;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, tag);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, tag, *((uint32_t*) nonce));

	memcpy (nonce_signed, nonce, length);
	nonce = nonce_signed;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_short_nonce (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	memcpy (nonce_signed, nonce, length);
	nonce = nonce_signed;
	length--;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_short_nonce_with_tag (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[4 + AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint32_t tag = 1234;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, tag);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, tag, *((uint32_t*) nonce));

	memcpy (nonce_signed, nonce, length);
	nonce = nonce_signed;
	length--;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_bad_rsa_signature (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_bad_ecc_signature (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + ECC_SIG_BAD_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN),
		MOCK_ARG (ECC_SIG_BAD_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += ECC_SIG_BAD_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_signed_wrong_nonce (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	nonce_signed[0] ^= 0x55;	// Change the signed nonce.

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_signed_wrong_nonce_with_tag (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[4 + AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];
	uint32_t tag = 1234;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, tag);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, tag, *((uint32_t*) nonce));

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	nonce_signed[0] ^= 0x55;	// Change the signed nonce.

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_no_nonce_generated (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	/* Generate a signed nonce.  We mock verification, so the actual signature doesn't matter. */
	memset (nonce_signed, 0x55, AUTH_CHALLENGE_NONCE_LENGTH);
	memcpy (&nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	length = AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN;
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_use_signed_nonce_twice (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_regenerate_nonce (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	size_t signed_length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	signed_length = length + RSA_ENCRYPT_LEN;

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	status = auth.base.authorize (&auth.base, &nonce, &signed_length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_regenerate_nonce_with_tag (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	size_t signed_length;
	uint32_t tag = 1234;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init_with_tag (&auth, &rng.base, &hash.base, &ecc.base,
		ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN, &verification.base, tag);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, tag, *((uint32_t*) nonce));

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	signed_length = length + RSA_ENCRYPT_LEN;

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);
	CuAssertIntEquals (test, tag, *((uint32_t*) nonce));

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	status = auth.base.authorize (&auth.base, &nonce, &signed_length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_use_nonce_after_bad_rsa_signature (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_use_nonce_after_bad_ecc_signature (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + ECC_SIG_BAD_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN),
		MOCK_ARG (ECC_SIG_BAD_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += ECC_SIG_BAD_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_BAD, ECC_SIG_BAD_LEN), MOCK_ARG (ECC_SIG_BAD_LEN));
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_use_nonce_after_signed_wrong_nonce (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	nonce_signed[0] ^= 0x55;	// Change the signed nonce.

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS_TMP (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = mock_validate (&verification.mock);
	CuAssertIntEquals (test, 0, status);

	/* Restore the original signed nonce. */
	nonce_signed[0] ^= 0x55;

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length - RSA_ENCRYPT_LEN,
		nonce_hash, sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_null (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (NULL, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, nonce);

	status = auth.base.authorize (&auth.base, NULL, &length);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, nonce);

	status = auth.base.authorize (&auth.base, &nonce, NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, NULL, nonce);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_no_nonce_rng_error (CuTest *test)
{
	struct rng_engine_mock rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (AUTH_CHALLENGE_NONCE_LENGTH), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);
	CuAssertPtrEquals (test, NULL, nonce);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_no_nonce_hash_error (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	struct hash_engine_mock hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (AUTH_CHALLENGE_NONCE_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);
	CuAssertPtrEquals (test, NULL, nonce);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_no_nonce_sign_error (CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	struct ecc_engine_mock ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	size_t length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	status |= mock_expect (&ecc.mock, ecc.base.get_signature_max_length, &ecc, 73,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.sign, &ecc, ECC_ENGINE_SIGN_FAILED,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (73));
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, ECC_ENGINE_SIGN_FAILED, status);
	CuAssertPtrEquals (test, NULL, nonce);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void authorization_challenge_test_authorize_regenerate_nonce_rng_error (CuTest *test)
{
	struct rng_engine_mock rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	size_t signed_length;

	TEST_START;

	status = rng_mock_init (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng, 0,
		MOCK_ARG (AUTH_CHALLENGE_NONCE_LENGTH), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&rng.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 0);

	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	signed_length = length + RSA_ENCRYPT_LEN;

	status = mock_expect (&rng.mock, rng.base.generate_random_buffer, &rng,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (AUTH_CHALLENGE_NONCE_LENGTH), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	nonce = nonce_signed;
	status = auth.base.authorize (&auth.base, &nonce, &signed_length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&rng);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_regenerate_nonce_hash_error (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	struct hash_engine_mock hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	size_t signed_length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (AUTH_CHALLENGE_NONCE_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_output (&hash.mock, 2, SIG_HASH_TEST, SHA256_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	signed_length = length + RSA_ENCRYPT_LEN;

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (AUTH_CHALLENGE_NONCE_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	nonce = nonce_signed;
	status = auth.base.authorize (&auth.base, &nonce, &signed_length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_regenerate_nonce_sign_error (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	struct ecc_engine_mock ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	size_t signed_length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.init_key_pair, &ecc, 0,
		MOCK_ARG_PTR_CONTAINS (ECC_PRIVKEY_DER, ECC_PRIVKEY_DER_LEN),
		MOCK_ARG (ECC_PRIVKEY_DER_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG (NULL));
	status |= mock_expect_save_arg (&ecc.mock, 2, 0);

	status |= mock_expect (&ecc.mock, ecc.base.get_signature_max_length, &ecc, 73,
		MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.sign, &ecc, ECC_SIG_TEST_LEN,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (73));
	status |= mock_expect_output (&ecc.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, 4);

	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);
	signed_length = length + RSA_ENCRYPT_LEN;

	status = mock_expect (&ecc.mock, ecc.base.sign, &ecc, ECC_ENGINE_SIGN_FAILED,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (73));
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, ECC_ENGINE_SIGN_FAILED, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	status = auth.base.authorize (&auth.base, &nonce, &signed_length);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&ecc.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&ecc.mock, ecc.base.release_key_pair, &ecc, 0, MOCK_ARG_SAVED_ARG (0),
		MOCK_ARG (NULL));
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	status = ecc_mock_validate_and_release (&ecc);
	CuAssertIntEquals (test, 0, status);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void authorization_challenge_test_authorize_with_signed_nonce_hash_error (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	struct hash_engine_mock hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (AUTH_CHALLENGE_NONCE_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_output (&hash.mock, 2, SIG_HASH_TEST, SHA256_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (length), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_with_signed_nonce_verify_error (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED, MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_use_nonce_after_hash_error (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	struct hash_engine_mock hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (AUTH_CHALLENGE_NONCE_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_output (&hash.mock, 2, SIG_HASH_TEST, SHA256_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	status = mock_validate (&hash.mock);
	CuAssertIntEquals (test, 0, status);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, HASH_ENGINE_SHA256_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (length), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = mock_expect (&hash.mock, hash.base.calculate_sha256, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (length - RSA_ENCRYPT_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);
	status |= mock_expect_output (&hash.mock, 2, SIG_HASH_TEST2, SHA256_HASH_LENGTH, 3);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST2, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}

static void authorization_challenge_test_authorize_use_nonce_after_verify_error (
	CuTest *test)
{
	RNG_TESTING_ENGINE rng;
	HASH_TESTING_ENGINE hash;
	ECC_TESTING_ENGINE ecc;
	struct signature_verification_mock verification;
	struct authorization_challenge auth;
	int status;
	uint8_t *nonce;
	uint8_t nonce_signed[AUTH_CHALLENGE_NONCE_LENGTH + ECC_SIG_TEST_LEN + RSA_ENCRYPT_LEN + 32];
	size_t length;
	uint8_t nonce_hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = RNG_TESTING_ENGINE_INIT (&rng);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&ecc);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = authorization_challenge_init (&auth, &rng.base, &hash.base, &ecc.base, ECC_PRIVKEY_DER,
		ECC_PRIVKEY_DER_LEN, &verification.base);
	CuAssertIntEquals (test, 0, status);

	nonce = NULL;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, AUTHORIZATION_CHALLENGE, status);
	CuAssertPtrNotNull (test, nonce);

	/* Sign the nonce.  We mock verification, so the actual signature doesn't matter. */
	memcpy (nonce_signed, nonce, length);
	memcpy (&nonce_signed[length], RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN);

	status = hash.base.calculate_sha256 (&hash.base, nonce_signed, length, nonce_hash,
		sizeof (nonce_hash));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED, MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	nonce = nonce_signed;
	length += RSA_ENCRYPT_LEN;
	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (nonce_hash, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));
	CuAssertIntEquals (test, 0, status);

	status = auth.base.authorize (&auth.base, &nonce, &length);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	authorization_challenge_release (&auth);

	RNG_TESTING_ENGINE_RELEASE (&rng);
	HASH_TESTING_ENGINE_RELEASE (&hash);
	ECC_TESTING_ENGINE_RELEASE (&ecc);
}


TEST_SUITE_START (authorization_challenge);

TEST (authorization_challenge_test_init);
TEST (authorization_challenge_test_init_null);
TEST (authorization_challenge_test_init_key_error);
TEST (authorization_challenge_test_init_sig_length_error);
TEST (authorization_challenge_test_init_with_tag);
TEST (authorization_challenge_test_init_with_tag_null);
TEST (authorization_challenge_test_init_with_tag_key_error);
TEST (authorization_challenge_test_init_with_tag_sig_length_error);
TEST (authorization_challenge_test_release_null);
TEST (authorization_challenge_test_authorize_no_nonce);
TEST (authorization_challenge_test_authorize_no_nonce_with_tag);
TEST (authorization_challenge_test_authorize_with_signed_nonce);
TEST (authorization_challenge_test_authorize_with_signed_nonce_with_tag);
TEST (authorization_challenge_test_authorize_no_signature);
TEST (authorization_challenge_test_authorize_no_signature_with_tag);
TEST (authorization_challenge_test_authorize_short_nonce);
TEST (authorization_challenge_test_authorize_short_nonce_with_tag);
TEST (authorization_challenge_test_authorize_bad_rsa_signature);
TEST (authorization_challenge_test_authorize_bad_ecc_signature);
TEST (authorization_challenge_test_authorize_signed_wrong_nonce);
TEST (authorization_challenge_test_authorize_signed_wrong_nonce_with_tag);
TEST (authorization_challenge_test_authorize_no_nonce_generated);
TEST (authorization_challenge_test_authorize_use_signed_nonce_twice);
TEST (authorization_challenge_test_authorize_regenerate_nonce);
TEST (authorization_challenge_test_authorize_regenerate_nonce_with_tag);
TEST (authorization_challenge_test_authorize_use_nonce_after_bad_rsa_signature);
TEST (authorization_challenge_test_authorize_use_nonce_after_bad_ecc_signature);
TEST (authorization_challenge_test_authorize_use_nonce_after_signed_wrong_nonce);
TEST (authorization_challenge_test_authorize_null);
TEST (authorization_challenge_test_authorize_no_nonce_rng_error);
TEST (authorization_challenge_test_authorize_no_nonce_hash_error);
TEST (authorization_challenge_test_authorize_no_nonce_sign_error);
TEST (authorization_challenge_test_authorize_regenerate_nonce_rng_error);
TEST (authorization_challenge_test_authorize_regenerate_nonce_hash_error);
TEST (authorization_challenge_test_authorize_regenerate_nonce_sign_error);
TEST (authorization_challenge_test_authorize_with_signed_nonce_hash_error);
TEST (authorization_challenge_test_authorize_with_signed_nonce_verify_error);
TEST (authorization_challenge_test_authorize_use_nonce_after_hash_error);
TEST (authorization_challenge_test_authorize_use_nonce_after_verify_error);

TEST_SUITE_END;
