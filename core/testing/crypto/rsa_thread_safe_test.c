// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/rsa_thread_safe.h"
#include "testing/mock/crypto/rsa_mock.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"


TEST_SUITE_LABEL ("rsa_thread_safe");


/*******************
 * Test cases
 *******************/

static void rsa_thread_safe_test_init (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.generate_key);
	CuAssertPtrNotNull (test, engine.base.init_private_key);
	CuAssertPtrNotNull (test, engine.base.init_public_key);
	CuAssertPtrNotNull (test, engine.base.release_key);
	CuAssertPtrNotNull (test, engine.base.get_private_key_der);
	CuAssertPtrNotNull (test, engine.base.get_public_key_der);
	CuAssertPtrNotNull (test, engine.base.decrypt);
	CuAssertPtrNotNull (test, engine.base.sig_verify);

	status = rsa_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_init_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (NULL, &mock.base);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = rsa_thread_safe_init (&engine, NULL);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = rsa_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void rsa_thread_safe_test_release_null (CuTest *test)
{
	TEST_START;

	rsa_thread_safe_release (NULL);
}

static void rsa_thread_safe_test_generate_key (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.generate_key, &mock, 0, MOCK_ARG (&key),
		MOCK_ARG (2048));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key (&engine.base, &key, 2048);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_generate_key_error (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.generate_key, &mock, RSA_ENGINE_GENERATE_KEY_FAILED,
		MOCK_ARG (&key), MOCK_ARG (2048));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key (&engine.base, &key, 2048);
	CuAssertIntEquals (test, RSA_ENGINE_GENERATE_KEY_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_generate_key_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_key (NULL, &key, 2048);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_init_private_key (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.init_private_key, &mock, 0, MOCK_ARG (&key),
		MOCK_ARG (RSA_PRIVKEY_DER), MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_init_private_key_error (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.init_private_key, &mock, RSA_ENGINE_NOT_PRIVATE_KEY,
		MOCK_ARG (&key), MOCK_ARG (RSA_PRIVKEY_DER), MOCK_ARG (RSA_PRIVKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (&engine.base, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_NOT_PRIVATE_KEY, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_init_private_key_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_private_key (NULL, &key, RSA_PRIVKEY_DER,
		RSA_PRIVKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_init_public_key (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.init_public_key, &mock, 0, MOCK_ARG (&key),
		MOCK_ARG (RSA_PUBKEY_DER), MOCK_ARG (RSA_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.init_public_key (&engine.base, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_init_public_key_error (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.init_public_key, &mock,
		RSA_ENGINE_PUBLIC_KEY_FAILED, MOCK_ARG (&key), MOCK_ARG (RSA_PUBKEY_DER),
		MOCK_ARG (RSA_PUBKEY_DER_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (&engine.base, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_PUBLIC_KEY_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.init_public_key (&engine.base, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_init_public_key_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_public_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.init_public_key (NULL, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.init_public_key (&engine.base, &key, RSA_PUBKEY_DER, RSA_PUBKEY_DER_LEN);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_release_key (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.release_key, &mock, 0, MOCK_ARG (&key));
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key (&engine.base, &key);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_release_key_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.release_key (NULL, &key);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_get_private_key_der (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_private_key_der, &mock, 0, MOCK_ARG (&key),
		MOCK_ARG (&der), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_get_private_key_der_error (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_private_key_der, &mock,
		RSA_ENGINE_PRIVATE_KEY_DER_FAILED, MOCK_ARG (&key), MOCK_ARG (&der), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, RSA_ENGINE_PRIVATE_KEY_DER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_get_private_key_der_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_private_key_der (NULL, &key, &der, &length);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_get_public_key_der (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_public_key_der, &mock, 0, MOCK_ARG (&key),
		MOCK_ARG (&der), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_get_public_key_der_error (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.get_public_key_der, &mock,
		RSA_ENGINE_PUBLIC_KEY_DER_FAILED, MOCK_ARG (&key), MOCK_ARG (&der), MOCK_ARG (&length));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (&engine.base, &key, &der, &length);
	CuAssertIntEquals (test, RSA_ENGINE_PUBLIC_KEY_DER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_get_public_key_der_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	uint8_t *der;
	size_t length;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_public_key_der (NULL, &key, &der, &length);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_decrypt (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.decrypt, &mock, 4, MOCK_ARG (&key),
		MOCK_ARG (RSA_LABEL_ENCRYPT_TEST), MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LABEL),
		MOCK_ARG (RSA_ENCRYPT_LABEL_LEN), MOCK_ARG (HASH_TYPE_SHA1), MOCK_ARG (message),
		MOCK_ARG (sizeof (message)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_LABEL_ENCRYPT_TEST, RSA_ENCRYPT_LEN,
		(uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN, HASH_TYPE_SHA1, (uint8_t*) message,
		sizeof (message));
	CuAssertIntEquals (test, 4, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_decrypt_error (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.decrypt, &mock, RSA_ENGINE_DECRYPT_FAILED,
		MOCK_ARG (&key), MOCK_ARG (RSA_LABEL_ENCRYPT_TEST), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LABEL), MOCK_ARG (RSA_ENCRYPT_LABEL_LEN), MOCK_ARG (HASH_TYPE_SHA1),
		MOCK_ARG (message), MOCK_ARG (sizeof (message)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (&engine.base, &key, RSA_LABEL_ENCRYPT_TEST, RSA_ENCRYPT_LEN,
		(uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN, HASH_TYPE_SHA1, (uint8_t*) message,
		sizeof (message));
	CuAssertIntEquals (test, RSA_ENGINE_DECRYPT_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_decrypt_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;
	char message[RSA_ENCRYPT_LEN];

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt (NULL, &key, RSA_LABEL_ENCRYPT_TEST, RSA_ENCRYPT_LEN,
		(uint8_t*) RSA_ENCRYPT_LABEL, RSA_ENCRYPT_LABEL_LEN, HASH_TYPE_SHA1, (uint8_t*) message,
		sizeof (message));
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_sig_verify (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.sig_verify, &mock, 0, MOCK_ARG (&RSA_PUBLIC_KEY),
		MOCK_ARG (RSA_SIGNATURE_TEST), MOCK_ARG (RSA_ENCRYPT_LEN), MOCK_ARG (SIG_HASH_TEST),
		MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_sig_verify_error (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.sig_verify, &mock, RSA_ENGINE_BAD_SIGNATURE,
		MOCK_ARG (&RSA_PUBLIC_KEY), MOCK_ARG (RSA_SIGNATURE_TEST), MOCK_ARG (RSA_ENCRYPT_LEN),
		MOCK_ARG (SIG_HASH_TEST), MOCK_ARG (SIG_HASH_LEN));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (&engine.base, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}

static void rsa_thread_safe_test_sig_verify_null (CuTest *test)
{
	struct rsa_engine_thread_safe engine;
	struct rsa_engine_mock mock;
	struct rsa_private_key key;
	int status;

	TEST_START;

	status = rsa_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.sig_verify (NULL, &RSA_PUBLIC_KEY, RSA_SIGNATURE_TEST,
		RSA_ENCRYPT_LEN, SIG_HASH_TEST, SIG_HASH_LEN);
	CuAssertIntEquals (test, RSA_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_key (&engine.base, &key, 2048);

	rsa_mock_release (&mock);
	rsa_thread_safe_release (&engine);
}


TEST_SUITE_START (rsa_thread_safe);

TEST (rsa_thread_safe_test_init);
TEST (rsa_thread_safe_test_init_null);
TEST (rsa_thread_safe_test_release_null);
TEST (rsa_thread_safe_test_generate_key);
TEST (rsa_thread_safe_test_generate_key_error);
TEST (rsa_thread_safe_test_generate_key_null);
TEST (rsa_thread_safe_test_init_private_key);
TEST (rsa_thread_safe_test_init_private_key_error);
TEST (rsa_thread_safe_test_init_private_key_null);
TEST (rsa_thread_safe_test_init_public_key);
TEST (rsa_thread_safe_test_init_public_key_error);
TEST (rsa_thread_safe_test_init_public_key_null);
TEST (rsa_thread_safe_test_release_key);
TEST (rsa_thread_safe_test_release_key_null);
TEST (rsa_thread_safe_test_get_private_key_der);
TEST (rsa_thread_safe_test_get_private_key_der_error);
TEST (rsa_thread_safe_test_get_private_key_der_null);
TEST (rsa_thread_safe_test_get_public_key_der);
TEST (rsa_thread_safe_test_get_public_key_der_error);
TEST (rsa_thread_safe_test_get_public_key_der_null);
TEST (rsa_thread_safe_test_decrypt);
TEST (rsa_thread_safe_test_decrypt_error);
TEST (rsa_thread_safe_test_decrypt_null);
TEST (rsa_thread_safe_test_sig_verify);
TEST (rsa_thread_safe_test_sig_verify_error);
TEST (rsa_thread_safe_test_sig_verify_null);

TEST_SUITE_END;
