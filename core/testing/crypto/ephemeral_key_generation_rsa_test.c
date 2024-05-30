// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "platform_api.h"
#include "testing.h"
#include "crypto/ephemeral_key_generation_rsa.h"
#include "crypto/ephemeral_key_generation_rsa_static.h"
#include "crypto/rsa_mbedtls.h"
#include "crypto/rsa_thread_safe.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/signature_testing.h"
#include "testing/mock/crypto/rsa_mock.h"


TEST_SUITE_LABEL ("ephemeral_key_generation_rsa");

/**
 * Dependencies for testing the ephemeral rsa key generation.
 */
struct ephemeral_key_generation_rsa_testing {
	struct ephemeral_key_generation_rsa key_gen_rsa;	/**< ephemeral key generation rsa object */
	struct rsa_engine_thread_safe engine;				/**< RSA thread safe object to use rsa engine */
	struct rsa_engine_mock mock;						/**< Mock object of the rsa engine */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param key_gen_rsa Testing dependencies to initialize.
 */
static void ephemeral_key_generation_rsa_testing_init_dependencies (CuTest *test,
	struct ephemeral_key_generation_rsa_testing *key_gen_rsa_test)
{
	int status;

	status = rsa_mock_init (&key_gen_rsa_test->mock);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&key_gen_rsa_test->engine, &key_gen_rsa_test->mock.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param key_gen_rsa Testing dependencies to initialize.
 */
static void ephemeral_key_generation_rsa_testing_release_dependencies (CuTest *test,
	struct ephemeral_key_generation_rsa_testing *key_gen_rsa_test)
{
	rsa_thread_safe_release (&key_gen_rsa_test->engine);

	rsa_mock_release (&key_gen_rsa_test->mock);
}

/*******************
 * Test cases
 *******************/
static void ephemeral_key_generation_rsa_test_init (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {0};
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test.key_gen_rsa,
		&key_gen_rsa_test.engine.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_static_init (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {
		.key_gen_rsa = ephemeral_key_generation_rsa_static_init (&key_gen_rsa_test.engine.base)
	};

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

	ephemeral_key_generation_rsa_release (&key_gen_rsa_test.key_gen_rsa);

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_init_null_input (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {0};
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (NULL, &key_gen_rsa_test.engine.base);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test.key_gen_rsa, NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = ephemeral_key_generation_rsa_init (NULL, NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_static_init_with_null_input (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {
		.key_gen_rsa = ephemeral_key_generation_rsa_static_init (NULL),
	};

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	CuAssertPtrEquals (test, NULL, key_gen_rsa_test.key_gen_rsa.engine);

	ephemeral_key_generation_rsa_release (&key_gen_rsa_test.key_gen_rsa);
	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {0};
	struct rsa_private_key rsa_key;
	size_t length;
	uint8_t *key = NULL;
	int key_size = 3072;
	int status;

	TEST_START;

	key = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key);

	memcpy (key, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test.key_gen_rsa,
		&key_gen_rsa_test.engine.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

#if (defined RSA_ENABLE_PRIVATE_KEY)
	/* Set mock expectation */
	status = mock_expect (&key_gen_rsa_test.mock.mock, key_gen_rsa_test.mock.base.generate_key,
		&key_gen_rsa_test.mock, 0, MOCK_ARG_PTR (&rsa_key), MOCK_ARG (key_size));

	status |= mock_expect (&key_gen_rsa_test.mock.mock,
		key_gen_rsa_test.mock.base.get_private_key_der,	&key_gen_rsa_test.mock,	0,
		MOCK_ARG_PTR (&rsa_key), MOCK_ARG_PTR (&key), MOCK_ARG_PTR (&length));
	status |= mock_expect_output (&key_gen_rsa_test.mock.mock, 1, &key, RSA3K_PRIVKEY_DER_LEN, -1);
	status |= mock_expect_output (&key_gen_rsa_test.mock.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&key_gen_rsa_test.mock.mock,	key_gen_rsa_test.mock.base.release_key,
		&key_gen_rsa_test.mock,	0, MOCK_ARG_PTR (&rsa_key));

	CuAssertIntEquals (test, 0, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, &key, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertStrEquals (test, (char*) RSA3K_PRIVKEY_DER, (char*) key);
	CuAssertIntEquals (test, RSA3K_PRIVKEY_DER_LEN, length);

	if (key != NULL) {
		platform_free (key);
	}
#else
	UNUSED (rsa_key);
	UNUSED (length);
	UNUSED (key);
	UNUSED (key_size);
#endif

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_with_static_init (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {
		.key_gen_rsa = ephemeral_key_generation_rsa_static_init (&key_gen_rsa_test.engine.base),
	};

	struct rsa_private_key rsa_key;
	size_t length;
	uint8_t *key = NULL;
	int key_size = 3072;
	int status;

	TEST_START;

	key = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key);

	memcpy (key, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

#if (defined RSA_ENABLE_PRIVATE_KEY)
	/* Set mock expectation */
	status = mock_expect (&key_gen_rsa_test.mock.mock, key_gen_rsa_test.mock.base.generate_key,
		&key_gen_rsa_test.mock, 0, MOCK_ARG_PTR (&rsa_key), MOCK_ARG (key_size));

	status |= mock_expect (&key_gen_rsa_test.mock.mock,
		key_gen_rsa_test.mock.base.get_private_key_der,	&key_gen_rsa_test.mock,	0,
		MOCK_ARG_PTR (&rsa_key), MOCK_ARG_PTR (&key), MOCK_ARG_PTR (&length));
	status |= mock_expect_output (&key_gen_rsa_test.mock.mock, 1, &key, RSA3K_PRIVKEY_DER_LEN, -1);
	status |= mock_expect_output (&key_gen_rsa_test.mock.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&key_gen_rsa_test.mock.mock,	key_gen_rsa_test.mock.base.release_key,
		&key_gen_rsa_test.mock,	0, MOCK_ARG_PTR (&rsa_key));

	CuAssertIntEquals (test, 0, status);

#else
	UNUSED (rsa_key);
	UNUSED (length);
	UNUSED (key);
	UNUSED (key_size);
#endif

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, &key, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertStrEquals (test, (char*) RSA3K_PRIVKEY_DER, (char*) key);
	CuAssertIntEquals (test, RSA3K_PRIVKEY_DER_LEN, length);

	if (key != NULL) {
		platform_free (key);
	}

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_with_mbedtls_thread_safe_rsa_engine_init
	(CuTest *test)
{
	struct ephemeral_key_generation_rsa key_gen_rsa = {0};
	struct rsa_engine_thread_safe rsa_safe_thread;
	struct rsa_engine_mbedtls engine;
	int key_size = 2048;
	uint8_t *key = NULL;
	size_t key_length = 0;
	int status;

	TEST_START;

	status = rsa_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = rsa_thread_safe_init (&rsa_safe_thread, &engine.base);
	CuAssertIntEquals (test, 0, status);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa, rsa_safe_thread.engine);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_gen_rsa.engine);

	status = key_gen_rsa.base.generate_key (&key_gen_rsa.base, key_size, &key, &key_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertTrue (test,
		((key_length >= (RSA_PRIVKEY_DER_LEN - 3)) && (key_length <= (RSA_PRIVKEY_DER_LEN + 3))));
	CuAssertPtrNotNull (test, key);

	if (key != NULL) {
		platform_free (key);
	}

	ephemeral_key_generation_rsa_release (&key_gen_rsa);

	rsa_mbedtls_release (&engine);
}

static void ephemeral_key_generation_rsa_test_generate_key_invalid_input (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {0};
	uint8_t *key = NULL;
	size_t key_length = 0;
	int key_size = 2048;
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test.key_gen_rsa,
		&key_gen_rsa_test.engine.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (NULL, key_size, &key, &key_length);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, NULL, &key_length);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, &key, NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (NULL, key_size, NULL, NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_with_generate_key_failed (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	struct rsa_private_key rsa_key;
	size_t key_length = 0;
	uint8_t *key = NULL;
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test.key_gen_rsa,
		&key_gen_rsa_test.engine.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

#if (defined RSA_ENABLE_PRIVATE_KEY)
	status = mock_expect (&key_gen_rsa_test.mock.mock, key_gen_rsa_test.mock.base.generate_key,
		&key_gen_rsa_test.mock, RSA_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG_PTR (&rsa_key),
		MOCK_ARG (2048));
	CuAssertIntEquals (test, 0, status);

#else
	UNUSED (rsa_key);
	UNUSED (key);
#endif

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		2048, &key, &key_length);
	CuAssertIntEquals (test, RSA_ENGINE_GENERATE_KEY_FAILED, status);
	CuAssertIntEquals (test, 0, key_length);
	CuAssertPtrEquals (test, key, NULL);

	ephemeral_key_generation_rsa_release (&key_gen_rsa_test.key_gen_rsa);

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_with_get_private_key_der_failed (
	CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	struct rsa_private_key rsa_key;
	size_t key_length = 0;
	uint8_t *key = NULL;
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test.key_gen_rsa,
		&key_gen_rsa_test.engine.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

#if (defined RSA_ENABLE_PRIVATE_KEY)
	status = mock_expect (&key_gen_rsa_test.mock.mock, key_gen_rsa_test.mock.base.generate_key,
		&key_gen_rsa_test.mock, 0, MOCK_ARG_PTR (&rsa_key),	MOCK_ARG (2048));

	status |= mock_expect (&key_gen_rsa_test.mock.mock,
		key_gen_rsa_test.mock.base.get_private_key_der,	&key_gen_rsa_test.mock,
		RSA_ENGINE_NO_MEMORY, MOCK_ARG_PTR (&rsa_key), MOCK_ARG_PTR (&key),
		MOCK_ARG_PTR (&key_length));

	status |= mock_expect (&key_gen_rsa_test.mock.mock,	key_gen_rsa_test.mock.base.release_key,
		&key_gen_rsa_test.mock,	0, MOCK_ARG_PTR (&rsa_key));

	CuAssertIntEquals (test, 0, status);

#else
	UNUSED (rsa_key);
	UNUSED (key);
#endif
	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		2048, &key, &key_length);
	CuAssertIntEquals (test, RSA_ENGINE_NO_MEMORY, status);
	CuAssertIntEquals (test, 0, key_length);
	CuAssertPtrEquals (test, key, NULL);

	ephemeral_key_generation_rsa_release (&key_gen_rsa_test.key_gen_rsa);
	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

// *INDENT-OFF*
TEST_SUITE_START (ephemeral_key_generation_rsa);

TEST (ephemeral_key_generation_rsa_test_init);
TEST (ephemeral_key_generation_rsa_test_static_init);
TEST (ephemeral_key_generation_rsa_test_static_init_with_null_input);
TEST (ephemeral_key_generation_rsa_test_init_null_input);
TEST (ephemeral_key_generation_rsa_test_generate_key);
TEST (ephemeral_key_generation_rsa_test_generate_key_with_static_init);
TEST (ephemeral_key_generation_rsa_test_generate_key_with_mbedtls_thread_safe_rsa_engine_init);
TEST (ephemeral_key_generation_rsa_test_generate_key_invalid_input);
TEST (ephemeral_key_generation_rsa_test_generate_key_with_generate_key_failed);
TEST (ephemeral_key_generation_rsa_test_generate_key_with_get_private_key_der_failed);

TEST_SUITE_END;
// *INDENT-ON*
