// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/authorization_global.h"
#include "common/authorization_global_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/common/authorizing_signature_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"


TEST_SUITE_LABEL ("authorization_global");


/**
 * Dependencies for testing authorization that requires a authenticated challenge.
 */
struct authorization_global_testing {
	HASH_TESTING_ENGINE (hash);							/**< Hash engine for testing */
	struct signature_verification_mock verification;	/**< Mock for signature verification. */
	struct authorizing_signature_mock data;				/**< Mock for the authorized data parser. */
	struct authorization_global test;					/**< Authorization manager under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to initialize.
 */
static void authorization_global_testing_init_dependencies (CuTest *test,
	struct authorization_global_testing *auth)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&auth->hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&auth->verification);
	CuAssertIntEquals (test, 0, status);

	status = authorizing_signature_mock_init (&auth->data);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to release all testing dependencies.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to release.
 */
static void authorization_global_testing_release_dependencies (CuTest *test,
	struct authorization_global_testing *auth)
{
	int status;

	HASH_TESTING_ENGINE_RELEASE (&auth->hash);

	status = signature_verification_mock_validate_and_release (&auth->verification);
	status |= authorizing_signature_mock_validate_and_release (&auth->data);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an authentication manager for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies.
 * @param key The authorizing key to use.
 * @param length Length of the authorizing key.
 * @param auth_hash Signature hash algorithm to use.
 */
static void authorization_global_testing_init (CuTest *test,
	struct authorization_global_testing *auth, const uint8_t *key, size_t length,
	enum hash_type auth_hash)
{
	int status;

	authorization_global_testing_init_dependencies (test, auth);

	status = mock_expect (&auth->verification.mock, auth->verification.base.is_key_valid,
		&auth->verification, 0, MOCK_ARG_PTR_CONTAINS (key, length), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = authorization_global_init (&auth->test, &auth->data.base, &auth->hash.base,
		&auth->verification.base, key, length, auth_hash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a static authentication manager for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies.
 * @param key The authorizing key to use.
 * @param length Length of the authorizing key.
 */
static void authorization_global_testing_init_static (CuTest *test,
	struct authorization_global_testing *auth, const uint8_t *key, size_t length)
{
	int status;

	authorization_global_testing_init_dependencies (test, auth);

	status = mock_expect (&auth->verification.mock, auth->verification.base.is_key_valid,
		&auth->verification, 0, MOCK_ARG_PTR_CONTAINS (key, length), MOCK_ARG (length));
	CuAssertIntEquals (test, 0, status);

	status = authorization_global_check_init (&auth->test);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release authentication test components.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to release.
 */
static void authorization_global_testing_release (CuTest *test,
	struct authorization_global_testing *auth)
{
	authorization_global_release (&auth->test);
	authorization_global_testing_release_dependencies (test, auth);
}


/*******************
 * Test cases
 *******************/

static void authorization_global_test_init (CuTest *test)
{
	struct authorization_global_testing auth;
	int status;

	TEST_START;

	authorization_global_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.verification.mock, auth.verification.base.is_key_valid,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = authorization_global_init (&auth.test, &auth.data.base, &auth.hash.base,
		&auth.verification.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.test.base.authorize);

	authorization_global_testing_release (test, &auth);
}

static void authorization_global_test_init_null (CuTest *test)
{
	struct authorization_global_testing auth;
	int status;

	TEST_START;

	authorization_global_testing_init_dependencies (test, &auth);

	status = authorization_global_init (NULL, &auth.data.base, &auth.hash.base,
		&auth.verification.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_global_init (&auth.test, NULL, &auth.hash.base, &auth.verification.base,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_global_init (&auth.test, &auth.data.base, NULL, &auth.verification.base,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_global_init (&auth.test, &auth.data.base, &auth.hash.base, NULL,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	authorization_global_testing_release_dependencies (test, &auth);
}

static void authorization_global_test_init_invalid_key (CuTest *test)
{
	struct authorization_global_testing auth;
	int status;

	TEST_START;

	authorization_global_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.verification.mock, auth.verification.base.is_key_valid,
		&auth.verification, SIG_VERIFICATION_INVALID_KEY,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = authorization_global_init (&auth.test, &auth.data.base, &auth.hash.base,
		&auth.verification.base, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	authorization_global_testing_release_dependencies (test, &auth);
}

static void authorization_global_test_init_invalid_hash_algorithm (CuTest *test)
{
	struct authorization_global_testing auth;
	int status;

	TEST_START;

	authorization_global_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.verification.mock, auth.verification.base.is_key_valid,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = authorization_global_init (&auth.test, &auth.data.base, &auth.hash.base,
		&auth.verification.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_INVALID);
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	authorization_global_testing_release_dependencies (test, &auth);
}

static void authorization_global_test_static_init (CuTest *test)
{
	struct authorization_global_testing auth = {
		.test = authorization_global_static_init (&auth.data.base, &auth.hash.base,
			&auth.verification.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, auth.test.base.authorize);

	authorization_global_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.verification.mock, auth.verification.base.is_key_valid,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = authorization_global_check_init (&auth.test);
	CuAssertIntEquals (test, 0, status);

	authorization_global_testing_release (test, &auth);
}

static void authorization_global_test_static_init_null (CuTest *test)
{
	struct authorization_global_testing auth;

	struct authorization_global null_data = authorization_global_static_init (NULL, &auth.hash.base,
		&auth.verification.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256);

	struct authorization_global null_hash = authorization_global_static_init (&auth.data.base, NULL,
		&auth.verification.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256);

	struct authorization_global null_verifcation =
		authorization_global_static_init (&auth.data.base, &auth.hash.base, NULL, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256);
	int status;

	TEST_START;

	authorization_global_testing_init_dependencies (test, &auth);

	status = authorization_global_check_init (NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_global_check_init (&null_data);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_global_check_init (&null_hash);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	status = authorization_global_check_init (&null_verifcation);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);

	authorization_global_testing_release_dependencies (test, &auth);
}

static void authorization_global_test_static_init_invalid_key (CuTest *test)
{
	struct authorization_global_testing auth = {
		.test = authorization_global_static_init (&auth.data.base, &auth.hash.base,
			&auth.verification.base, ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN, HASH_TYPE_SHA256)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, auth.test.base.authorize);

	authorization_global_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.verification.mock, auth.verification.base.is_key_valid,
		&auth.verification, SIG_VERIFICATION_INVALID_KEY,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY2_DER, ECC_PUBKEY2_DER_LEN),
		MOCK_ARG (ECC_PUBKEY2_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = authorization_global_check_init (&auth.test);
	CuAssertIntEquals (test, SIG_VERIFICATION_INVALID_KEY, status);

	authorization_global_testing_release_dependencies (test, &auth);
}

static void authorization_global_test_static_init_invalid_hash_algorithm (CuTest *test)
{
	struct authorization_global_testing auth = {
		.test = authorization_global_static_init (&auth.data.base, &auth.hash.base,
			&auth.verification.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_INVALID)
	};
	int status;

	TEST_START;

	authorization_global_testing_init_dependencies (test, &auth);

	status = mock_expect (&auth.verification.mock, auth.verification.base.is_key_valid,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = authorization_global_check_init (&auth.test);
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	authorization_global_testing_release_dependencies (test, &auth);
}

static void authorization_global_test_release_null (CuTest *test)
{
	TEST_START;

	authorization_global_release (NULL);
}

static void authorization_global_test_authorize (CuTest *test)
{
	struct authorization_global_testing auth;
	uint8_t auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN + ECC_SIG_TEST_LEN];
	const uint8_t *token = auth_data;
	size_t data_len = sizeof (auth_data);
	const uint8_t *signature = &auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN];
	size_t sig_length = ECC_SIG_TEST_LEN;
	int status;

	TEST_START;

	memcpy (auth_data, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN);
	memcpy (&auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);

	authorization_global_testing_init (test, &auth, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_signature, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, data_len), MOCK_ARG (data_len), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &signature, sizeof (signature), -1);
	status |= mock_expect_output (&auth.data.mock, 3, &sig_length, sizeof (sig_length), -1);

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.verify_signature,
		&auth.verification, 0,
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (signature, sig_length),
		MOCK_ARG (sig_length));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	authorization_global_testing_release (test, &auth);
}

static void authorization_global_test_authorize_static_init (CuTest *test)
{
	struct authorization_global_testing auth = {
		.test = authorization_global_static_init (&auth.data.base, &auth.hash.base,
			&auth.verification.base, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256)
	};
	uint8_t auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN + ECC_SIG_TEST_LEN];
	const uint8_t *token = auth_data;
	size_t data_len = sizeof (auth_data);
	const uint8_t *signature = &auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN];
	size_t sig_length = ECC_SIG_TEST_LEN;
	int status;

	TEST_START;

	memcpy (auth_data, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN);
	memcpy (&auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);

	authorization_global_testing_init_static (test, &auth, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN);

	status = mock_expect (&auth.data.mock, auth.data.base.get_signature, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, data_len), MOCK_ARG (data_len), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &signature, sizeof (signature), -1);
	status |= mock_expect_output (&auth.data.mock, 3, &sig_length, sizeof (sig_length), -1);

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.verify_signature,
		&auth.verification, 0,
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (signature, sig_length),
		MOCK_ARG (sig_length));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	authorization_global_testing_release (test, &auth);
}

#ifdef HASH_ENABLE_SHA384
static void authorization_global_test_authorize_sha384 (CuTest *test)
{
	struct authorization_global_testing auth;
	uint8_t auth_data[HASH_TESTING_FULL_BLOCK_2048_LEN + ECC384_SIG_TEST_LEN];
	const uint8_t *token = auth_data;
	size_t data_len = sizeof (auth_data);
	const uint8_t *signature = &auth_data[HASH_TESTING_FULL_BLOCK_2048_LEN];
	size_t sig_length = ECC384_SIG_TEST_LEN;
	int status;

	TEST_START;

	memcpy (auth_data, HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN);
	memcpy (&auth_data[HASH_TESTING_FULL_BLOCK_2048_LEN], ECC384_SIGNATURE_TEST,
		ECC384_SIG_TEST_LEN);

	authorization_global_testing_init (test, &auth, ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN,
		HASH_TYPE_SHA384);

	status = mock_expect (&auth.data.mock, auth.data.base.get_signature, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, data_len), MOCK_ARG (data_len), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &signature, sizeof (signature), -1);
	status |= mock_expect_output (&auth.data.mock, 3, &sig_length, sizeof (sig_length), -1);

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.verify_signature,
		&auth.verification, 0,
		MOCK_ARG_PTR_CONTAINS (SHA384_FULL_BLOCK_2048_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (signature, sig_length),
		MOCK_ARG (sig_length));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	authorization_global_testing_release (test, &auth);
}

static void authorization_global_test_authorize_sha384_static_init (CuTest *test)
{
	struct authorization_global_testing auth = {
		.test = authorization_global_static_init (&auth.data.base, &auth.hash.base,
			&auth.verification.base, ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN, HASH_TYPE_SHA384)
	};
	uint8_t auth_data[HASH_TESTING_FULL_BLOCK_2048_LEN + ECC384_SIG_TEST_LEN];
	const uint8_t *token = auth_data;
	size_t data_len = sizeof (auth_data);
	const uint8_t *signature = &auth_data[HASH_TESTING_FULL_BLOCK_2048_LEN];
	size_t sig_length = ECC384_SIG_TEST_LEN;
	int status;

	TEST_START;

	memcpy (auth_data, HASH_TESTING_FULL_BLOCK_2048, HASH_TESTING_FULL_BLOCK_2048_LEN);
	memcpy (&auth_data[HASH_TESTING_FULL_BLOCK_2048_LEN], ECC384_SIGNATURE_TEST,
		ECC384_SIG_TEST_LEN);

	authorization_global_testing_init_static (test, &auth, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN);

	status = mock_expect (&auth.data.mock, auth.data.base.get_signature, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, data_len), MOCK_ARG (data_len), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &signature, sizeof (signature), -1);
	status |= mock_expect_output (&auth.data.mock, 3, &sig_length, sizeof (sig_length), -1);

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.verify_signature,
		&auth.verification, 0,
		MOCK_ARG_PTR_CONTAINS (SHA384_FULL_BLOCK_2048_HASH, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (signature, sig_length),
		MOCK_ARG (sig_length));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	authorization_global_testing_release (test, &auth);
}
#endif

static void authorization_global_test_authorize_null (CuTest *test)
{
	struct authorization_global_testing auth;
	uint8_t auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN + ECC_SIG_TEST_LEN];
	const uint8_t *token = auth_data;
	size_t data_len = sizeof (auth_data);
	int status;

	TEST_START;

	memcpy (auth_data, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN);
	memcpy (&auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);

	authorization_global_testing_init (test, &auth, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		HASH_TYPE_SHA256);

	status = auth.test.base.authorize (NULL, &token, &data_len);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	status = auth.test.base.authorize (&auth.test.base, NULL, &data_len);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	status = auth.test.base.authorize (&auth.test.base, &token, NULL);
	CuAssertIntEquals (test, AUTHORIZATION_INVALID_ARGUMENT, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	authorization_global_testing_release (test, &auth);
}

static void authorization_global_test_authorize_no_authorized_data (CuTest *test)
{
	struct authorization_global_testing auth;
	const uint8_t *token;
	size_t data_len;
	int status;

	TEST_START;

	authorization_global_testing_init (test, &auth, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		HASH_TYPE_SHA256);

	token = NULL;
	data_len = 10;

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	token = (uint8_t*) &data_len;
	data_len = 0;

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);

	authorization_global_testing_release (test, &auth);
}

static void authorization_global_test_authorize_get_signature_error (CuTest *test)
{
	struct authorization_global_testing auth;
	uint8_t auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN + ECC_SIG_TEST_LEN];
	const uint8_t *token = auth_data;
	size_t data_len = sizeof (auth_data);
	int status;

	TEST_START;

	memcpy (auth_data, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN);
	memcpy (&auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);

	authorization_global_testing_init (test, &auth, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_signature, &auth.data,
		AUTH_SIGNATURE_GET_SIG_FAILED, MOCK_ARG_PTR_CONTAINS (auth_data, data_len),
		MOCK_ARG (data_len), MOCK_ARG_NOT_NULL,	MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, AUTH_SIGNATURE_GET_SIG_FAILED, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	authorization_global_testing_release (test, &auth);
}

static void authorization_global_test_authorize_not_authorized_bad_signature (CuTest *test)
{
	struct authorization_global_testing auth;
	uint8_t auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN + ECC_SIG_TEST_LEN];
	const uint8_t *token = auth_data;
	size_t data_len = sizeof (auth_data);
	const uint8_t *signature = &auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN];
	size_t sig_length = ECC_SIG_TEST_LEN;
	int status;

	TEST_START;

	memcpy (auth_data, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN);
	memcpy (&auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);

	authorization_global_testing_init (test, &auth, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_signature, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, data_len), MOCK_ARG (data_len), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &signature, sizeof (signature), -1);
	status |= mock_expect_output (&auth.data.mock, 3, &sig_length, sizeof (sig_length), -1);

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.verify_signature,
		&auth.verification, SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (signature, sig_length),
		MOCK_ARG (sig_length));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, AUTHORIZATION_NOT_AUTHORIZED, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	authorization_global_testing_release (test, &auth);
}

static void authorization_global_test_authorize_signature_verify_error (CuTest *test)
{
	struct authorization_global_testing auth;
	uint8_t auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN + ECC_SIG_TEST_LEN];
	const uint8_t *token = auth_data;
	size_t data_len = sizeof (auth_data);
	const uint8_t *signature = &auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN];
	size_t sig_length = ECC_SIG_TEST_LEN;
	int status;

	TEST_START;

	memcpy (auth_data, HASH_TESTING_FULL_BLOCK_1024, HASH_TESTING_FULL_BLOCK_1024_LEN);
	memcpy (&auth_data[HASH_TESTING_FULL_BLOCK_1024_LEN], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);

	authorization_global_testing_init (test, &auth, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		HASH_TYPE_SHA256);

	status = mock_expect (&auth.data.mock, auth.data.base.get_signature, &auth.data, 0,
		MOCK_ARG_PTR_CONTAINS (auth_data, data_len), MOCK_ARG (data_len), MOCK_ARG_NOT_NULL,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.data.mock, 2, &signature, sizeof (signature), -1);
	status |= mock_expect_output (&auth.data.mock, 3, &sig_length, sizeof (sig_length), -1);

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.verify_signature,
		&auth.verification, SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (SHA256_FULL_BLOCK_1024_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_PTR_CONTAINS (signature, sig_length),
		MOCK_ARG (sig_length));

	status |= mock_expect (&auth.verification.mock, auth.verification.base.set_verification_key,
		&auth.verification, 0, MOCK_ARG_PTR (NULL), MOCK_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.base.authorize (&auth.test.base, &token, &data_len);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);
	CuAssertPtrEquals (test, (void*) auth_data, token);
	CuAssertIntEquals (test, sizeof (auth_data), data_len);

	authorization_global_testing_release (test, &auth);
}


// *INDENT-OFF*
TEST_SUITE_START (authorization_global);

TEST (authorization_global_test_init);
TEST (authorization_global_test_init_null);
TEST (authorization_global_test_init_invalid_key);
TEST (authorization_global_test_init_invalid_hash_algorithm);
TEST (authorization_global_test_static_init);
TEST (authorization_global_test_static_init_null);
TEST (authorization_global_test_static_init_invalid_key);
TEST (authorization_global_test_static_init_invalid_hash_algorithm);
TEST (authorization_global_test_release_null);
TEST (authorization_global_test_authorize);
TEST (authorization_global_test_authorize_static_init);
#ifdef HASH_ENABLE_SHA384
TEST (authorization_global_test_authorize_sha384);
TEST (authorization_global_test_authorize_sha384_static_init);
#endif
TEST (authorization_global_test_authorize_null);
TEST (authorization_global_test_authorize_no_authorized_data);
TEST (authorization_global_test_authorize_get_signature_error);
TEST (authorization_global_test_authorize_not_authorized_bad_signature);
TEST (authorization_global_test_authorize_signature_verify_error);

TEST_SUITE_END;
// *INDENT-ON*
