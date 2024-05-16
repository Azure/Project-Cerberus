// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "asn1/ecc_der_util.h"
#include "common/auth_token.h"
#include "common/auth_token_static.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/hash_testing.h"
#include "testing/engines/ecc_testing_engine.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rng_testing_engine.h"
#include "testing/engines/x509_testing_engine.h"
#include "testing/mock/crypto/ecc_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/keystore/keystore_mock.h"
#include "testing/riot/riot_core_testing.h"


TEST_SUITE_LABEL ("auth_token");


/**
 * Dependencies for testing authorization token management.
 */
struct auth_token_testing {
	X509_TESTING_ENGINE x509;						/**< X.509 handler for the key manager. */
	struct keystore_mock keystore;					/**< Mock for the device keystore. */
	struct riot_keys keys;							/**< Device keys for the key manager. */
	struct riot_key_manager device_keys;			/**< Device key manager for testing. */
	RNG_TESTING_ENGINE rng;							/**< RNG for testing. */
	struct rng_engine_mock rng_mock;				/**< Mock for the RNG. */
	HASH_TESTING_ENGINE hash;						/**< Hash engine for testing. */
	struct hash_engine_mock hash_mock;				/**< Mock for the hash engine. */
	ECC_TESTING_ENGINE ecc;							/**< ECC engine for testing. */
	struct ecc_engine_mock ecc_mock;				/**< Mock for the ECC engine. */
	struct ecc_public_key token_key;				/**< Public key for token signing. */
	struct signature_verification_mock authority;	/**< Mock for authority signature verification. */
	uint8_t *buffer;								/**< Buffer to use for token generation. */
	size_t buffer_length;							/**< Length of the token buffer. */
	size_t data_length;								/**< Length of the token data section. */
	size_t nonce_length;							/**< Length of the token nonce. */
	size_t sig_offset;								/**< Offset in the token where the signature will be. */
	struct auth_token_state state;					/**< Variable context for the token handler. */
	struct auth_token test;							/**< Token handler under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to initialize.
 * @param data_length Length of the additional token data.
 * @param nonce_length Length of the token nonce.
 * @param key_size Size of the token signing key.
 */
static void auth_token_testing_init_dependencies (CuTest *test, struct auth_token_testing *auth,
	size_t data_length, size_t nonce_length, size_t key_size)
{
	uint8_t *dev_id_der = NULL;
	int status;

	auth->data_length = data_length;
	auth->nonce_length = nonce_length;
	auth->sig_offset = data_length + nonce_length;
	auth->buffer_length = data_length + nonce_length;

	/* Initialize the device keys. */
	status = X509_TESTING_ENGINE_INIT (&auth->x509);
	CuAssertIntEquals (test, 0, status);

	status = keystore_mock_init (&auth->keystore);
	CuAssertIntEquals (test, 0, status);

	switch (key_size) {
		case ECC_KEY_LENGTH_256:
			auth->keys.devid_csr = RIOT_CORE_DEVID_CSR;
			auth->keys.devid_csr_length = RIOT_CORE_DEVID_CSR_LEN;
			auth->keys.devid_cert = RIOT_CORE_DEVID_CERT;
			auth->keys.devid_cert_length = RIOT_CORE_DEVID_CERT_LEN;
			auth->keys.alias_key = RIOT_CORE_ALIAS_KEY;
			auth->keys.alias_key_length = RIOT_CORE_ALIAS_KEY_LEN;
			auth->keys.alias_cert = RIOT_CORE_ALIAS_CERT;
			auth->keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_LEN;

			auth->buffer_length += ECC_DER_P256_ECDSA_MAX_LENGTH;
			break;

		case ECC_KEY_LENGTH_384:
			auth->keys.devid_csr = RIOT_CORE_DEVID_CSR_384;
			auth->keys.devid_csr_length = RIOT_CORE_DEVID_CSR_384_LEN;
			auth->keys.devid_cert = RIOT_CORE_DEVID_CERT_384;
			auth->keys.devid_cert_length = RIOT_CORE_DEVID_CERT_384_LEN;
			auth->keys.alias_key = RIOT_CORE_ALIAS_KEY_384;
			auth->keys.alias_key_length = RIOT_CORE_ALIAS_KEY_384_LEN;
			auth->keys.alias_cert = RIOT_CORE_ALIAS_CERT_384;
			auth->keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_384_LEN;

			auth->buffer_length += ECC_DER_P384_ECDSA_MAX_LENGTH;
			break;

		case ECC_KEY_LENGTH_521:
			auth->keys.devid_csr = RIOT_CORE_DEVID_CSR_521;
			auth->keys.devid_csr_length = RIOT_CORE_DEVID_CSR_521_LEN;
			auth->keys.devid_cert = RIOT_CORE_DEVID_CERT_521;
			auth->keys.devid_cert_length = RIOT_CORE_DEVID_CERT_521_LEN;
			auth->keys.alias_key = RIOT_CORE_ALIAS_KEY_521;
			auth->keys.alias_key_length = RIOT_CORE_ALIAS_KEY_521_LEN;
			auth->keys.alias_cert = RIOT_CORE_ALIAS_CERT_521;
			auth->keys.alias_cert_length = RIOT_CORE_ALIAS_CERT_521_LEN;

			auth->buffer_length += ECC_DER_P521_ECDSA_MAX_LENGTH;
			break;
	}

	status = mock_expect (&auth->keystore.mock, auth->keystore.base.load_key, &auth->keystore,
		KEYSTORE_NO_KEY, MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output_tmp (&auth->keystore.mock, 1, &dev_id_der, sizeof (dev_id_der),
		-1);

	CuAssertIntEquals (test, 0, status);

	status = riot_key_manager_init_static (&auth->device_keys, &auth->keystore.base, &auth->keys,
		&auth->x509.base);
	CuAssertIntEquals (test, 0, status);

	/* Initialize the rest of the dependencies. */
	auth->buffer = platform_malloc (auth->buffer_length);
	CuAssertPtrNotNull (test, auth->buffer);

	status = RNG_TESTING_ENGINE_INIT (&auth->rng);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&auth->rng_mock);
	CuAssertIntEquals (test, 0, status);

	status = HASH_TESTING_ENGINE_INIT (&auth->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&auth->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = ECC_TESTING_ENGINE_INIT (&auth->ecc);
	CuAssertIntEquals (test, 0, status);

	status = ecc_mock_init (&auth->ecc_mock);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&auth->authority);
	CuAssertIntEquals (test, 0, status);

	/* Get the token public key for verifying generated tokens. */
	status = auth->ecc.base.init_key_pair (&auth->ecc.base, auth->keys.alias_key,
		auth->keys.alias_key_length, NULL, &auth->token_key);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to release.
 */
static void auth_token_testing_release_dependencies (CuTest *test, struct auth_token_testing *auth)
{
	int status;

	platform_free (auth->buffer);
	auth->ecc.base.release_key_pair (&auth->ecc.base, NULL, &auth->token_key);

	status = keystore_mock_validate_and_release (&auth->keystore);
	status |= rng_mock_validate_and_release (&auth->rng_mock);
	status |= hash_mock_validate_and_release (&auth->hash_mock);
	status |= ecc_mock_validate_and_release (&auth->ecc_mock);
	status |= signature_verification_mock_validate_and_release (&auth->authority);

	CuAssertIntEquals (test, 0, status);

	riot_key_manager_release (&auth->device_keys);
	X509_TESTING_ENGINE_RELEASE (&auth->x509);
	RNG_TESTING_ENGINE_RELEASE (&auth->rng);
	HASH_TESTING_ENGINE_RELEASE (&auth->hash);
	ECC_TESTING_ENGINE_RELEASE (&auth->ecc);
}

/**
 * Initialize authorization token handling for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies.
 * @param data_length Length of the additional token data.
 * @param nonce_length Length of the token nonce.
 * @param key_size Size of the token signing key.
 * @param auth_key The authority signing key.
 * @param auth_key_length Length of the authority key.
 * @param sig_hash Hash algorithm for token signature.
 * @param validity_time Time until token expiration.
 */
static void auth_token_testing_init (CuTest *test, struct auth_token_testing *auth,
	size_t data_length, size_t nonce_length, size_t key_size, const uint8_t *auth_key,
	size_t auth_key_length, enum hash_type sig_hash, uint32_t validity_time)
{
	int status;

	auth_token_testing_init_dependencies (test, auth, data_length, nonce_length, key_size);

	status = auth_token_init (&auth->test, &auth->state, &auth->rng.base, &auth->hash.base,
		&auth->ecc.base, &auth->device_keys, auth_key, auth_key_length, &auth->authority.base,
		auth->data_length, auth->nonce_length, sig_hash, validity_time);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize authorization token handling with a user buffer for testing.
 *
 * @param test The test framework.
 * @param auth Testing dependencies.
 * @param data_length Length of the additional token data.
 * @param nonce_length Length of the token nonce.
 * @param key_size Size of the token signing key.
 * @param auth_key The authority signing key.
 * @param auth_key_length Length of the authority key.
 * @param sig_hash Hash algorithm for token signature.
 * @param validity_time Time until token expiration.
 */
static void auth_token_testing_init_with_buffer (CuTest *test, struct auth_token_testing *auth,
	size_t data_length, size_t nonce_length, size_t key_size, const uint8_t *auth_key,
	size_t auth_key_length, enum hash_type sig_hash, uint32_t validity_time)
{
	int status;

	auth_token_testing_init_dependencies (test, auth, data_length, nonce_length, key_size);

	status = auth_token_init_with_buffer (&auth->test, &auth->state, &auth->rng.base,
		&auth->hash.base, &auth->ecc.base, &auth->device_keys, auth_key, auth_key_length,
		&auth->authority.base, auth->data_length, auth->nonce_length, sig_hash, validity_time,
		auth->buffer, auth->buffer_length);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release authorization token test components and validate all mocks.
 *
 * @param test The test framework.
 * @param auth Testing dependencies to release.
 * @param token The token handler to release.
 */
static void auth_token_testing_release (CuTest *test, struct auth_token_testing *auth,
	struct auth_token *token)
{
	auth_token_testing_release_dependencies (test, auth);
	auth_token_release (token);
}


/*******************
 * Test cases
 *******************/

static void auth_token_test_init (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.test.new_token);
	CuAssertPtrNotNull (test, auth.test.verify_data);
	CuAssertPtrNotNull (test, auth.test.invalidate);

	/* Inspect internal config to confirm correct buffer sizing. */
	CuAssertIntEquals (test, auth.buffer_length, auth.test.buffer_length);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_init_token_data (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 16, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	/* Inspect internal config to confirm correct buffer sizing. */
	CuAssertIntEquals (test, auth.buffer_length, auth.test.buffer_length);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_init_null (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init (NULL, &auth.state, &auth.rng.base, &auth.hash.base, &auth.ecc.base,
		&auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, NULL, &auth.rng.base, &auth.hash.base, &auth.ecc.base,
		&auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, &auth.state, NULL, &auth.hash.base, &auth.ecc.base,
		&auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, NULL, &auth.ecc.base,
		&auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,	NULL,
		&auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, NULL, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, 0, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, NULL,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, 0, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_init_key_error (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	CuAssertIntEquals (test, 0, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_init_sig_length_error (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 0);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.get_signature_max_length,
		&auth.ecc_mock, ECC_ENGINE_SIG_LENGTH_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_LENGTH_FAILED, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_init_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, auth.test.new_token);
	CuAssertPtrNotNull (test, auth.test.verify_data);
	CuAssertPtrNotNull (test, auth.test.invalidate);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_init_with_buffer_token_data (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 16, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_init_with_buffer_null (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init_with_buffer (NULL, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, NULL, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, NULL, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, NULL,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		NULL, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, NULL, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, NULL, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, 0, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, NULL,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, 0, HASH_TYPE_SHA256, 0, auth.buffer, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, NULL, auth.buffer_length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_init_with_buffer_small_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer,
		auth.buffer_length - 1);
	CuAssertIntEquals (test, AUTH_TOKEN_SMALL_BUFFER, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_init_with_buffer_small_buffer_token_data (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 16, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer,
		auth.buffer_length - 1);
	CuAssertIntEquals (test, AUTH_TOKEN_SMALL_BUFFER, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_init_with_buffer_key_error (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	CuAssertIntEquals (test, 0, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer,
		auth.buffer_length);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_init_with_buffer_sig_length_error (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 0);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.get_signature_max_length,
		&auth.ecc_mock, ECC_ENGINE_SIG_LENGTH_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth_token_init_with_buffer (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0, auth.buffer,
		auth.buffer_length);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_LENGTH_FAILED, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, test_static.new_token);
	CuAssertPtrNotNull (test, test_static.verify_data);
	CuAssertPtrNotNull (test, test_static.invalidate);

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_static_init_token_data (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 24;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_static_init_null (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (NULL);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.state = &auth.state;
	test_static.rng = NULL;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.rng = &auth.rng.base;
	test_static.hash = NULL;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.hash = &auth.hash.base;
	test_static.ecc = NULL;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.ecc = &auth.ecc.base;
	test_static.device_key = NULL;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.device_key = &auth.device_keys;
	test_static.authority_key = NULL;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.authority_key = ECC_PUBKEY_DER;
	test_static.auth_key_length = 0;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.auth_key_length = ECC_PUBKEY_DER_LEN;
	test_static.authority = NULL;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.authority = &auth.authority.base;
	test_static.nonce_length = 0;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.nonce_length = nonce_length;
	test_static.buffer = NULL;
	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_static_init_small_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer) - 1);
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_SMALL_BUFFER, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_static_init_small_buffer_token_data (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 24;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer) - 1);
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_SMALL_BUFFER, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_static_init_wrong_signature_length (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH - 1;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_WRONG_SIG_LENGTH, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_static_init_key_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	CuAssertIntEquals (test, 0, status);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_static_init_sig_length_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 0);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.get_signature_max_length,
		&auth.ecc_mock, ECC_ENGINE_SIG_LENGTH_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_LENGTH_FAILED, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, test_static.new_token);
	CuAssertPtrNotNull (test, test_static.verify_data);
	CuAssertPtrNotNull (test, test_static.invalidate);

	/* Inspect internal config to confirm correct buffer sizing. */
	CuAssertIntEquals (test, (data_length + nonce_length + sig_length), test_static.buffer_length);

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_dynamic_buffer_static_init_token_data (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 24;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, test_static.new_token);
	CuAssertPtrNotNull (test, test_static.verify_data);
	CuAssertPtrNotNull (test, test_static.invalidate);

	/* Inspect internal config to confirm correct buffer sizing. */
	CuAssertIntEquals (test, (data_length + nonce_length + sig_length), test_static.buffer_length);

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_dynamic_buffer_static_init_null (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (NULL);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.state = NULL;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.state = &auth.state;
	test_static.rng = NULL;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.rng = &auth.rng.base;
	test_static.hash = NULL;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.hash = &auth.hash.base;
	test_static.ecc = NULL;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.ecc = &auth.ecc.base;
	test_static.device_key = NULL;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.device_key = &auth.device_keys;
	test_static.authority_key = NULL;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.authority_key = ECC_PUBKEY_DER;
	test_static.auth_key_length = 0;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.auth_key_length = ECC_PUBKEY_DER_LEN;
	test_static.authority = NULL;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	test_static.authority = &auth.authority.base;
	test_static.nonce_length = 0;
	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_dynamic_buffer_static_init_wrong_signature_length (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH - 1;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, AUTH_TOKEN_WRONG_SIG_LENGTH, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_dynamic_buffer_static_init_key_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	CuAssertIntEquals (test, 0, status);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_dynamic_buffer_static_init_sig_length_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 0);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.get_signature_max_length,
		&auth.ecc_mock, ECC_ENGINE_SIG_LENGTH_FAILED, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, ECC_ENGINE_SIG_LENGTH_FAILED, status);

	auth_token_testing_release_dependencies (test, &auth);
}

static void auth_token_test_release_null (CuTest *test)
{
	TEST_START;

	auth_token_release (NULL);
}

static void auth_token_test_new_token (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, 0, 32, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, 0, 32, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, auth.buffer, (void*) token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, (void*) token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_SIZE_384) && (defined HASH_ENABLE_SHA384)
static void auth_token_test_new_token_sha384 (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, 0, 32, ECC_KEY_LENGTH_384, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN, HASH_TYPE_SHA384, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha384 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA384_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_sha384_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, 0, 32, ECC_KEY_LENGTH_384, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN, HASH_TYPE_SHA384, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, auth.buffer, (void*) token);

	status = auth.hash.base.calculate_sha384 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA384_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_sha384_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P384_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA384, 0, buffer, sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_384);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, (void*) token);

	status = auth.hash.base.calculate_sha384 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA384_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_sha384_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P384_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC384_PUBKEY_DER,
		ECC384_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA384, 0);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_384);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha384 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA384_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_SIZE_521) && (defined HASH_ENABLE_SHA512)
static void auth_token_test_new_token_sha512 (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, 0, 32, ECC_KEY_LENGTH_521, ECC521_PUBKEY_DER,
		ECC521_PUBKEY_DER_LEN, HASH_TYPE_SHA512, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha512 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA512_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_sha512_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, 0, 32, ECC_KEY_LENGTH_521, ECC521_PUBKEY_DER,
		ECC521_PUBKEY_DER_LEN, HASH_TYPE_SHA512, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, auth.buffer, (void*) token);

	status = auth.hash.base.calculate_sha512 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA512_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_sha512_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P521_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC521_PUBKEY_DER,
		ECC521_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA512, 0, buffer, sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_521);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, (void*) token);

	status = auth.hash.base.calculate_sha512 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA512_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_sha512_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P521_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC521_PUBKEY_DER,
		ECC521_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA512, 0);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_521);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha512 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA512_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}
#endif

static void auth_token_test_new_token_longer_nonce (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, 0, 64, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_longer_nonce_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, 0, 64, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, auth.buffer, (void*) token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_longer_nonce_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 64;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, (void*) token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_longer_nonce_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 64;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_context_data (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, HASH_TESTING_FULL_BLOCK_512_LEN, 32, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, token, auth.data_length);
	CuAssertIntEquals (test, 0, status);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_context_data_pad_short_data (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t expected[HASH_TESTING_FULL_BLOCK_512_LEN];

	TEST_START;

	memset (expected, 0, sizeof (expected));
	memcpy (expected, HASH_TESTING_FULL_BLOCK_512, HASH_TESTING_FULL_BLOCK_512_LEN - 16);

	auth_token_testing_init (test, &auth, HASH_TESTING_FULL_BLOCK_512_LEN, 32, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN - 16, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = testing_validate_array (expected, token, auth.data_length);
	CuAssertIntEquals (test, 0, status);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_context_data_no_data (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t expected[HASH_TESTING_FULL_BLOCK_512_LEN];

	TEST_START;

	memset (expected, 0, sizeof (expected));

	auth_token_testing_init (test, &auth, HASH_TESTING_FULL_BLOCK_512_LEN, 32, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = testing_validate_array (expected, token, auth.data_length);
	CuAssertIntEquals (test, 0, status);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_context_data_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, HASH_TESTING_FULL_BLOCK_512_LEN, 32,
		ECC_KEY_LENGTH_256, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, auth.buffer, (void*) token);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, token, auth.data_length);
	CuAssertIntEquals (test, 0, status);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_context_data_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, (void*) token);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, token, auth.data_length);
	CuAssertIntEquals (test, 0, status);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_context_data_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = HASH_TESTING_FULL_BLOCK_512_LEN;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, token, auth.data_length);
	CuAssertIntEquals (test, 0, status);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_with_expiration (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, 0, 32, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 100);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_with_expiration_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, 0, 32, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 500);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, auth.buffer, (void*) token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_with_expiration_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 1000, buffer,
		sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, (void*) token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_with_expiration_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 1500);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token,
		auth.data_length + auth.nonce_length, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = auth.ecc.base.verify (&auth.ecc.base, &auth.token_key, digest, SHA256_HASH_LENGTH,
		&token[auth.sig_offset], length - auth.sig_offset);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_new_token_null (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	auth_token_testing_init (test, &auth, 0, 32, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (NULL, NULL, 0, &token, &length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth.test.new_token (&auth.test, NULL, 0, NULL, &length);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, NULL);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_context_data_too_much_data (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	auth_token_testing_init (test, &auth, HASH_TESTING_FULL_BLOCK_512_LEN, 32, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN + 1, &token, &length);
	CuAssertIntEquals (test, AUTH_TOKEN_DATA_TOO_LONG, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_rng_error (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng_mock.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.rng_mock.mock, auth.rng_mock.base.generate_random_buffer,
		&auth.rng_mock, RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (auth.nonce_length), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_hash_error (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash_mock.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.hash_mock.mock, auth.hash_mock.base.calculate_sha256,
		&auth.hash_mock, HASH_ENGINE_SHA256_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (auth.nonce_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_key_error (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 0);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.get_signature_max_length,
		&auth.ecc_mock, ECC_DER_P256_ECDSA_MAX_LENGTH, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&auth.ecc_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_new_token_sign_error (CuTest *test)
{
	struct auth_token_testing auth;
	int status;
	const uint8_t *token;
	size_t length;

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, 0, 32, ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 0);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.get_signature_max_length,
		&auth.ecc_mock, ECC_DER_P256_ECDSA_MAX_LENGTH, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&auth.ecc_mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 1);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.sign, &auth.ecc_mock,
		ECC_ENGINE_SIGN_FAILED, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_DER_P256_ECDSA_MAX_LENGTH));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, ECC_ENGINE_SIGN_FAILED, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_SIZE_384) && (defined HASH_ENABLE_SHA384)
static void auth_token_test_verify_data_sha384 (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P384_ECDSA_MAX_LENGTH +
		aad_length + ECC384_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_384,
		ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN, HASH_TYPE_SHA384, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC384_SIGNATURE_TEST2, ECC384_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha384 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC384_PUBKEY_DER, ECC384_PUBKEY_DER_LEN),
		MOCK_ARG (ECC384_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA384_HASH_LENGTH),
		MOCK_ARG (SHA384_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC384_SIGNATURE_TEST2, ECC384_SIG_TEST2_LEN),
		MOCK_ARG (ECC384_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC384_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA384);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}
#endif

#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_SIZE_521) && (defined HASH_ENABLE_SHA512)
static void auth_token_test_verify_data_sha512 (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P521_ECDSA_MAX_LENGTH +
		aad_length + ECC521_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_521,
		ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN, HASH_TYPE_SHA512, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC521_SIGNATURE_TEST2, ECC521_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha512 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC521_PUBKEY_DER, ECC521_PUBKEY_DER_LEN),
		MOCK_ARG (ECC521_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA512_HASH_LENGTH),
		MOCK_ARG (SHA512_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC521_SIGNATURE_TEST2, ECC521_SIG_TEST2_LEN),
		MOCK_ARG (ECC521_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC521_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA512);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}
#endif

static void auth_token_test_verify_data_longer_nonce (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 64;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_context_data (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, HASH_TESTING_FULL_BLOCK_1024, data_length, &token,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_additional_authenticated_data (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = ECC521_PRIVKEY_DER_LEN;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Add the AAD and sign the token.  Verification is mocked, so the actual signature doesn't
	 * matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC521_PRIVKEY_DER, aad_length);
	length += aad_length;
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_token_offset (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 10;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, ECC384_PUBKEY, token_offset);
	memcpy (&token_signed[token_offset], token, length);
	length += token_offset;
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_context_data_aad_and_token_offset (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 10;
	const size_t data_length = HASH_TESTING_FULL_BLOCK_1024_LEN;
	const size_t nonce_length = 32;
	const size_t aad_length = ECC521_PRIVKEY_DER_LEN;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, HASH_TESTING_FULL_BLOCK_1024, data_length, &token,
		&length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, ECC384_PUBKEY, token_offset);
	memcpy (&token_signed[token_offset], token, length);
	length += token_offset;
	memcpy (&token_signed[length], ECC521_PRIVKEY_DER, aad_length);
	length += aad_length;
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_not_expired (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 5000);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	platform_msleep (500);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_same_token_twice (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	/* Verify the token again. */
	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, auth.buffer, (void*) token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, (void*) token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = test_static.verify_data (&test_static, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_verify_data_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = test_static.verify_data (&test_static, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_verify_data_null (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	int status;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_SIG_TEST_LEN +
		ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	/* Generate a random signed nonce. */
	memset (token_signed, 0x55, auth.nonce_length);
	memcpy (&token_signed[auth.nonce_length], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	memcpy (&token_signed[auth.nonce_length + ECC_SIG_TEST_LEN], ECC_SIGNATURE_TEST2,
		ECC_SIG_TEST2_LEN);

	status = auth.test.verify_data (NULL, token_signed, sizeof (token_signed), token_offset, 0,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	status = auth.test.verify_data (&auth.test, NULL, sizeof (token_signed), token_offset, 0,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_no_active_token (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	int status;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_SIG_TEST_LEN +
		ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	/* Generate a random signed nonce. */
	memset (token_signed, 0x55, auth.nonce_length);
	memcpy (&token_signed[auth.nonce_length], ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN);
	memcpy (&token_signed[auth.nonce_length + ECC_SIG_TEST_LEN], ECC_SIGNATURE_TEST2,
		ECC_SIG_TEST2_LEN);

	status = auth.test.verify_data (&auth.test, token_signed, sizeof (token_signed), token_offset,
		0, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_no_signature (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Verify the token without any authorizing signature. */
	memcpy (token_signed, token, length);
	status = auth.test.verify_data (&auth.test, token_signed, length, token_offset, aad_length,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_no_signature_with_aad (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = ECC521_PRIVKEY_DER_LEN;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Verify the token without any authorizing signature. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC521_PRIVKEY_DER, aad_length);
	length += aad_length;

	status = auth.test.verify_data (&auth.test, token_signed, length, token_offset, aad_length,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_short_token (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Length is less than the token data. */
	memcpy (token_signed, token, length);
	status = auth.test.verify_data (&auth.test, token_signed, length - 1, token_offset, aad_length,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_short_aad (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = ECC521_PRIVKEY_DER_LEN;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Length is less than the token plus the AAD. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC521_PRIVKEY_DER, aad_length);
	length += aad_length;

	status = auth.test.verify_data (&auth.test, token_signed, length - 1, token_offset, aad_length,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_short_token_offset (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 10;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Length is less than the token plus the offset. */
	memcpy (&token_signed[token_offset], token, length);
	length += token_offset;

	status = auth.test.verify_data (&auth.test, token_signed, length - 1, token_offset, aad_length,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_overflow_token_offset (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 10;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Length is less than the token plus the offset. */
	memcpy (&token_signed[token_offset], token, length);
	length += token_offset;
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);
	length += ECC_SIG_TEST2_LEN;

	status = auth.test.verify_data (&auth.test, token_signed, length, length, aad_length,
		HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_bad_signature (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, SIG_VERIFICATION_BAD_SIGNATURE,
		MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_signed_wrong_token (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);
	token_signed[8] ^= 0x55;	// Change the token data.

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_expired_token (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 100);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	platform_msleep (150);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_expired_token_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 100);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	platform_msleep (150);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_expired_token_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 200, buffer,
		sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrEquals (test, buffer, (void*) token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	platform_msleep (250);

	status = test_static.verify_data (&test_static, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_verify_data_expired_token_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 200);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	platform_msleep (250);

	status = test_static.verify_data (&test_static, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_verify_data_after_new_token (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	/* Generate the first token. */
	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	/* Get a new token.*/
	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);

	/* Verify with the old token. */
	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_after_new_token_rng_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng_mock.base, &auth.hash.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	/* Generate the first token. */
	status = mock_expect (&auth.rng_mock.mock, auth.rng_mock.base.generate_random_buffer,
		&auth.rng_mock, 0, MOCK_ARG (nonce_length), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&auth.rng_mock.mock, 1, SHA256_TEST_HASH, SHA256_HASH_LENGTH, 0);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	/* Get a new token.*/
	status = mock_expect (&auth.rng_mock.mock, auth.rng_mock.base.generate_random_buffer,
		&auth.rng_mock, RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (nonce_length), MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	/* Verify with the old token. */
	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_after_new_token_hash_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash_mock.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	/* Generate the first token. */
	status = mock_expect (&auth.hash_mock.mock, auth.hash_mock.base.calculate_sha256,
		&auth.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (auth.nonce_length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&auth.hash_mock.mock, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	/* Get a new token.*/
	status = mock_expect (&auth.hash_mock.mock, auth.hash_mock.base.calculate_sha256,
		&auth.hash_mock, HASH_ENGINE_SHA256_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (auth.nonce_length),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	/* Verify with the old token. */
	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_after_new_token_key_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 0);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.get_signature_max_length,
		&auth.ecc_mock, ECC_DER_P256_ECDSA_MAX_LENGTH, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&auth.ecc_mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Generate the first token. */
	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 1);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.sign, &auth.ecc_mock,
		ECC_SIG_TEST_LEN, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_DER_P256_ECDSA_MAX_LENGTH));
	status |= mock_expect_output (&auth.ecc_mock.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, 4);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = mock_validate (&auth.ecc_mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	/* Get a new token.*/
	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock,
		ECC_ENGINE_KEY_PAIR_FAILED,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, ECC_ENGINE_KEY_PAIR_FAILED, status);

	/* Verify with the old token. */
	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_after_new_token_sign_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 0);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.get_signature_max_length,
		&auth.ecc_mock, ECC_DER_P256_ECDSA_MAX_LENGTH, MOCK_ARG_SAVED_ARG (0));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (0), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash.base,
		&auth.ecc_mock.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&auth.ecc_mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Generate the first token. */
	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 1);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.sign, &auth.ecc_mock,
		ECC_SIG_TEST_LEN, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (ECC_DER_P256_ECDSA_MAX_LENGTH));
	status |= mock_expect_output (&auth.ecc_mock.mock, 3, ECC_SIGNATURE_TEST, ECC_SIG_TEST_LEN, 4);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (1), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = mock_validate (&auth.ecc_mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	/* Get a new token.*/
	status = mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.init_key_pair, &auth.ecc_mock, 0,
		MOCK_ARG_PTR_CONTAINS (RIOT_CORE_ALIAS_KEY, RIOT_CORE_ALIAS_KEY_LEN),
		MOCK_ARG (RIOT_CORE_ALIAS_KEY_LEN), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (NULL));
	status |= mock_expect_save_arg (&auth.ecc_mock.mock, 2, 2);

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.sign, &auth.ecc_mock,
		ECC_ENGINE_SIGN_FAILED, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (ECC_DER_P256_ECDSA_MAX_LENGTH));

	status |= mock_expect (&auth.ecc_mock.mock, auth.ecc_mock.base.release_key_pair, &auth.ecc_mock,
		0, MOCK_ARG_SAVED_ARG (2), MOCK_ARG_PTR (NULL));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, ECC_ENGINE_SIGN_FAILED, status);

	/* Verify with the old token. */
	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_hash_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init (&auth.test, &auth.state, &auth.rng.base, &auth.hash_mock.base,
		&auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, &auth.authority.base,
		auth.data_length, auth.nonce_length, HASH_TYPE_SHA256, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.hash_mock.mock, auth.hash_mock.base.calculate_sha256,
		&auth.hash_mock, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (auth.nonce_length), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&auth.hash_mock.mock, 2, SHA256_TEST_HASH, SHA256_HASH_LENGTH, 3);

	CuAssertIntEquals (test, 0, status);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = mock_expect (&auth.hash_mock.mock, auth.hash_mock.base.calculate_sha256,
		&auth.hash_mock, HASH_ENGINE_SHA256_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG_ANY,
		MOCK_ARG_NOT_NULL, MOCK_ARG_AT_LEAST (SHA256_HASH_LENGTH));
	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_set_key_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, SIG_VERIFICATION_SET_KEY_FAILED,
		MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN), MOCK_ARG (ECC_PUBKEY_DER_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, SIG_VERIFICATION_SET_KEY_FAILED, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_verify_data_verify_error (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t digest[HASH_MAX_HASH_LEN];
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	/* Sign the token.  Verification is mocked, so the actual signature doesn't matter. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.hash.base.calculate_sha256 (&auth.hash.base, token_signed, length, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&auth.authority.mock, auth.authority.base.set_verification_key,
		&auth.authority, 0, MOCK_ARG_PTR_CONTAINS (ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN),
		MOCK_ARG (ECC_PUBKEY_DER_LEN));

	status |= mock_expect (&auth.authority.mock, auth.authority.base.verify_signature,
		&auth.authority, SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (digest, SHA256_HASH_LENGTH), MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN),
		MOCK_ARG (ECC_SIG_TEST2_LEN));

	CuAssertIntEquals (test, 0, status);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_invalidate_no_active_token (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init (test, &auth, 0, 32, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.invalidate (&auth.test);
	CuAssertIntEquals (test, 0, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_invalidate_with_active_token (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.test.invalidate (&auth.test);
	CuAssertIntEquals (test, 0, status);

	/* Sign the token. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_invalidate_with_buffer (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_with_buffer (test, &auth, data_length, nonce_length, ECC_KEY_LENGTH_256,
		ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.new_token (&auth.test, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = auth.test.invalidate (&auth.test);
	CuAssertIntEquals (test, 0, status);

	/* Sign the token. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = auth.test.verify_data (&auth.test, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &auth.test);
}

static void auth_token_test_invalidate_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	uint8_t buffer[data_length + nonce_length + sig_length];
	struct auth_token test_static = auth_token_static_init (&auth.state, &auth.rng.base,
		&auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER, ECC_PUBKEY_DER_LEN,
		&auth.authority.base, data_length, nonce_length, sig_length, HASH_TYPE_SHA256, 0, buffer,
		sizeof (buffer));
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = test_static.invalidate (&test_static);
	CuAssertIntEquals (test, 0, status);

	/* Sign the token. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = test_static.verify_data (&test_static, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_invalidate_dynamic_buffer_static_init (CuTest *test)
{
	struct auth_token_testing auth;
	const size_t token_offset = 0;
	const size_t data_length = 0;
	const size_t nonce_length = 32;
	const size_t aad_length = 0;
	const size_t sig_length = ECC_DER_P256_ECDSA_MAX_LENGTH;
	struct auth_token test_static = auth_token_dynamic_buffer_static_init (&auth.state,
		&auth.rng.base, &auth.hash.base, &auth.ecc.base, &auth.device_keys, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, &auth.authority.base, data_length, nonce_length, sig_length,
		HASH_TYPE_SHA256, 0);
	int status;
	const uint8_t *token;
	size_t length;
	uint8_t token_signed[token_offset + data_length + nonce_length + ECC_DER_P256_ECDSA_MAX_LENGTH +
		aad_length + ECC_SIG_TEST2_LEN];

	TEST_START;

	auth_token_testing_init_dependencies (test, &auth, data_length, nonce_length,
		ECC_KEY_LENGTH_256);

	status = auth_token_init_dynamic_state (&test_static);
	CuAssertIntEquals (test, 0, status);

	status = test_static.new_token (&test_static, NULL, 0, &token, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, token);

	status = test_static.invalidate (&test_static);
	CuAssertIntEquals (test, 0, status);

	/* Sign the token. */
	memcpy (token_signed, token, length);
	memcpy (&token_signed[length], ECC_SIGNATURE_TEST2, ECC_SIG_TEST2_LEN);

	status = test_static.verify_data (&test_static, token_signed, length + ECC_SIG_TEST2_LEN,
		token_offset, aad_length, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, AUTH_TOKEN_NOT_VALID, status);

	auth_token_testing_release (test, &auth, &test_static);
}

static void auth_token_test_invalidate_null (CuTest *test)
{
	struct auth_token_testing auth;
	int status;

	TEST_START;

	auth_token_testing_init (test, &auth, 0, 32, ECC_KEY_LENGTH_256, ECC_PUBKEY_DER,
		ECC_PUBKEY_DER_LEN, HASH_TYPE_SHA256, 0);

	status = auth.test.invalidate (NULL);
	CuAssertIntEquals (test, AUTH_TOKEN_INVALID_ARGUMENT, status);

	auth_token_testing_release (test, &auth, &auth.test);
}


// *INDENT-OFF*
TEST_SUITE_START (auth_token);

TEST (auth_token_test_init);
TEST (auth_token_test_init_token_data);
TEST (auth_token_test_init_null);
TEST (auth_token_test_init_key_error);
TEST (auth_token_test_init_sig_length_error);
TEST (auth_token_test_init_with_buffer);
TEST (auth_token_test_init_with_buffer_token_data);
TEST (auth_token_test_init_with_buffer_null);
TEST (auth_token_test_init_with_buffer_small_buffer);
TEST (auth_token_test_init_with_buffer_small_buffer_token_data);
TEST (auth_token_test_init_with_buffer_key_error);
TEST (auth_token_test_init_with_buffer_sig_length_error);
TEST (auth_token_test_static_init);
TEST (auth_token_test_static_init_token_data);
TEST (auth_token_test_static_init_null);
TEST (auth_token_test_static_init_small_buffer);
TEST (auth_token_test_static_init_small_buffer_token_data);
TEST (auth_token_test_static_init_wrong_signature_length);
TEST (auth_token_test_static_init_key_error);
TEST (auth_token_test_static_init_sig_length_error);
TEST (auth_token_test_dynamic_buffer_static_init);
TEST (auth_token_test_dynamic_buffer_static_init_token_data);
TEST (auth_token_test_dynamic_buffer_static_init_null);
TEST (auth_token_test_dynamic_buffer_static_init_wrong_signature_length);
TEST (auth_token_test_dynamic_buffer_static_init_key_error);
TEST (auth_token_test_dynamic_buffer_static_init_sig_length_error);
TEST (auth_token_test_release_null);
TEST (auth_token_test_new_token);
TEST (auth_token_test_new_token_with_buffer);
TEST (auth_token_test_new_token_static_init);
TEST (auth_token_test_new_token_dynamic_buffer_static_init);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_SIZE_384) && (defined HASH_ENABLE_SHA384)
TEST (auth_token_test_new_token_sha384);
TEST (auth_token_test_new_token_sha384_with_buffer);
TEST (auth_token_test_new_token_sha384_static_init);
TEST (auth_token_test_new_token_sha384_dynamic_buffer_static_init);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_SIZE_521) && (defined HASH_ENABLE_SHA512)
TEST (auth_token_test_new_token_sha512);
TEST (auth_token_test_new_token_sha512_with_buffer);
TEST (auth_token_test_new_token_sha512_static_init);
TEST (auth_token_test_new_token_sha512_dynamic_buffer_static_init);
#endif
TEST (auth_token_test_new_token_longer_nonce);
TEST (auth_token_test_new_token_longer_nonce_with_buffer);
TEST (auth_token_test_new_token_longer_nonce_static_init);
TEST (auth_token_test_new_token_longer_nonce_dynamic_buffer_static_init);
TEST (auth_token_test_new_token_context_data);
TEST (auth_token_test_new_token_context_data_pad_short_data);
TEST (auth_token_test_new_token_context_data_no_data);
TEST (auth_token_test_new_token_context_data_with_buffer);
TEST (auth_token_test_new_token_context_data_static_init);
TEST (auth_token_test_new_token_context_data_dynamic_buffer_static_init);
TEST (auth_token_test_new_token_with_expiration);
TEST (auth_token_test_new_token_with_expiration_with_buffer);
TEST (auth_token_test_new_token_with_expiration_static_init);
TEST (auth_token_test_new_token_with_expiration_dynamic_buffer_static_init);
TEST (auth_token_test_new_token_null);
TEST (auth_token_test_new_token_context_data_too_much_data);
TEST (auth_token_test_new_token_rng_error);
TEST (auth_token_test_new_token_hash_error);
TEST (auth_token_test_new_token_key_error);
TEST (auth_token_test_new_token_sign_error);
TEST (auth_token_test_verify_data);
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_SIZE_384) && (defined HASH_ENABLE_SHA384)
TEST (auth_token_test_verify_data_sha384);
#endif
#if (ECC_MAX_KEY_LENGTH >= ECC_KEY_SIZE_521) && (defined HASH_ENABLE_SHA512)
TEST (auth_token_test_verify_data_sha512);
#endif
TEST (auth_token_test_verify_data_longer_nonce);
TEST (auth_token_test_verify_data_context_data);
TEST (auth_token_test_verify_data_additional_authenticated_data);
TEST (auth_token_test_verify_data_token_offset);
TEST (auth_token_test_verify_data_context_data_aad_and_token_offset);
TEST (auth_token_test_verify_data_not_expired);
TEST (auth_token_test_verify_data_same_token_twice);
TEST (auth_token_test_verify_data_with_buffer);
TEST (auth_token_test_verify_data_static_init);
TEST (auth_token_test_verify_data_dynamic_buffer_static_init);
TEST (auth_token_test_verify_data_null);
TEST (auth_token_test_verify_data_no_active_token);
TEST (auth_token_test_verify_data_no_signature);
TEST (auth_token_test_verify_data_no_signature_with_aad);
TEST (auth_token_test_verify_data_short_token);
TEST (auth_token_test_verify_data_short_aad);
TEST (auth_token_test_verify_data_short_token_offset);
TEST (auth_token_test_verify_data_overflow_token_offset);
TEST (auth_token_test_verify_data_bad_signature);
TEST (auth_token_test_verify_data_signed_wrong_token);
TEST (auth_token_test_verify_data_expired_token);
TEST (auth_token_test_verify_data_expired_token_with_buffer);
TEST (auth_token_test_verify_data_expired_token_static_init);
TEST (auth_token_test_verify_data_expired_token_dynamic_buffer_static_init);
TEST (auth_token_test_verify_data_after_new_token);
TEST (auth_token_test_verify_data_after_new_token_rng_error);
TEST (auth_token_test_verify_data_after_new_token_hash_error);
TEST (auth_token_test_verify_data_after_new_token_key_error);
TEST (auth_token_test_verify_data_after_new_token_sign_error);
TEST (auth_token_test_verify_data_hash_error);
TEST (auth_token_test_verify_data_set_key_error);
TEST (auth_token_test_verify_data_verify_error);
TEST (auth_token_test_invalidate_no_active_token);
TEST (auth_token_test_invalidate_with_active_token);
TEST (auth_token_test_invalidate_with_buffer);
TEST (auth_token_test_invalidate_static_init);
TEST (auth_token_test_invalidate_dynamic_buffer_static_init);
TEST (auth_token_test_invalidate_null);

TEST_SUITE_END;
// *INDENT-ON*
