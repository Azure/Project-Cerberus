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
#include "testing/crypto/rsa_testing.h"
#include "testing/mock/crypto/rsa_mock.h"


TEST_SUITE_LABEL ("ephemeral_key_generation_rsa");

/**
 * Dependencies for testing the ephemeral RSA key generation.
 */
struct ephemeral_key_generation_rsa_testing {
	struct ephemeral_key_generation_rsa key_gen_rsa;	/**< ephemeral key generation RSA object */
	struct rsa_engine_mock rsa;							/**< Mock object of the RSA engine */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param key_gen_rsa_test Testing dependencies to initialize.
 */
static void ephemeral_key_generation_rsa_testing_init_dependencies (CuTest *test,
	struct ephemeral_key_generation_rsa_testing *key_gen_rsa_test)
{
	int status;

	status = rsa_mock_init (&key_gen_rsa_test->rsa);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param key_gen_rsa_test Testing dependencies to initialize.
 */
static void ephemeral_key_generation_rsa_testing_release_dependencies (CuTest *test,
	struct ephemeral_key_generation_rsa_testing *key_gen_rsa_test)
{
	int status;

	status = rsa_mock_validate_and_release (&key_gen_rsa_test->rsa);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an RSA key generator for testing.
 *
 * @param test The test framework.
 * @param key_gen_rsa_test Testing components to initialize.
 */
static void ephemeral_key_generation_rsa_testing_init (CuTest *test,
	struct ephemeral_key_generation_rsa_testing *key_gen_rsa_test)
{
	int status;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test->key_gen_rsa,
		&key_gen_rsa_test->rsa.base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Release RSA key generator components and validate all mocks.
 *
 * @param test The test framework.
 * @param key_gen_rsa_test Testing components to release.
 */
static void ephemeral_key_generation_rsa_testing_release (CuTest *test,
	struct ephemeral_key_generation_rsa_testing *key_gen_rsa_test)
{
	ephemeral_key_generation_rsa_release (&key_gen_rsa_test->key_gen_rsa);
	ephemeral_key_generation_rsa_testing_release_dependencies (test, key_gen_rsa_test);
}

/*******************
 * Test cases
 *******************/

static void ephemeral_key_generation_rsa_test_init (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test.key_gen_rsa,
		&key_gen_rsa_test.rsa.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

	ephemeral_key_generation_rsa_testing_release (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_init_null_input (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	status = ephemeral_key_generation_rsa_init (NULL, &key_gen_rsa_test.rsa.base);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = ephemeral_key_generation_rsa_init (&key_gen_rsa_test.key_gen_rsa, NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = ephemeral_key_generation_rsa_init (NULL, NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_static_init (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {
		.key_gen_rsa = ephemeral_key_generation_rsa_static_init (&key_gen_rsa_test.rsa.base)
	};

	TEST_START;

	CuAssertPtrNotNull (test, key_gen_rsa_test.key_gen_rsa.engine);

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	ephemeral_key_generation_rsa_testing_release (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_release_null (CuTest *test)
{
	TEST_START;

	ephemeral_key_generation_rsa_release (NULL);
}

static void ephemeral_key_generation_rsa_test_generate_key (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	size_t length;
	uint8_t *key;
	int key_size = 3072;
	uint8_t key_out[4096];
	int status;

	TEST_START;

	key = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key);

	memcpy (key, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	ephemeral_key_generation_rsa_testing_init (test, &key_gen_rsa_test);

	/* Set mock expectation */
	status = mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.generate_key,
		&key_gen_rsa_test.rsa, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (key_size));
	status |= mock_expect_save_arg (&key_gen_rsa_test.rsa.mock, 0, 0);

	status |= mock_expect (&key_gen_rsa_test.rsa.mock,
		key_gen_rsa_test.rsa.base.get_private_key_der, &key_gen_rsa_test.rsa, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&length));
	status |= mock_expect_output (&key_gen_rsa_test.rsa.mock, 1, &key, sizeof (key), -1);
	status |= mock_expect_output (&key_gen_rsa_test.rsa.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.release_key,
		&key_gen_rsa_test.rsa, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, key_out, sizeof (key_out), &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA3K_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (RSA3K_PRIVKEY_DER, key_out, length);
	CuAssertIntEquals (test, 0, status);

	ephemeral_key_generation_rsa_testing_release (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_with_static_init (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test = {
		.key_gen_rsa = ephemeral_key_generation_rsa_static_init (&key_gen_rsa_test.rsa.base),
	};
	size_t length;
	uint8_t *key;
	int key_size = 4096;
	uint8_t key_out[4096];
	int status;

	TEST_START;

	key = platform_malloc (RSA4K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key);

	memcpy (key, RSA4K_PRIVKEY_DER, RSA4K_PRIVKEY_DER_LEN);

	ephemeral_key_generation_rsa_testing_init_dependencies (test, &key_gen_rsa_test);

	/* Set mock expectation */
	status = mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.generate_key,
		&key_gen_rsa_test.rsa, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (key_size));
	status |= mock_expect_save_arg (&key_gen_rsa_test.rsa.mock, 0, 0);

	status |= mock_expect (&key_gen_rsa_test.rsa.mock,
		key_gen_rsa_test.rsa.base.get_private_key_der, &key_gen_rsa_test.rsa, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&length));
	status |= mock_expect_output (&key_gen_rsa_test.rsa.mock, 1, &key, sizeof (key), -1);
	status |= mock_expect_output (&key_gen_rsa_test.rsa.mock, 2, &RSA4K_PRIVKEY_DER_LEN,
		sizeof (RSA4K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.release_key,
		&key_gen_rsa_test.rsa, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, key_out, sizeof (key_out), &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RSA4K_PRIVKEY_DER_LEN, length);

	status = testing_validate_array (RSA4K_PRIVKEY_DER, key_out, length);
	CuAssertIntEquals (test, 0, status);

	ephemeral_key_generation_rsa_testing_release_dependencies (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_invalid_input (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	size_t key_length = 0;
	uint8_t key_out[4096];
	int key_size = 2048;
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init (test, &key_gen_rsa_test);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (NULL, key_size, key_out,
		sizeof (key_out), &key_length);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, NULL, sizeof (key_out), &key_length);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, key_out, sizeof (key_out), NULL);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_INVALID_ARGUMENT, status);

	ephemeral_key_generation_rsa_testing_release (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_invalid_key_buffer_size (
	CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	size_t length;
	uint8_t *key;
	int key_size = 3072;
	uint8_t key_out[RSA3K_PRIVKEY_DER_LEN - 1];
	int status;

	TEST_START;

	key = platform_malloc (RSA3K_PRIVKEY_DER_LEN);
	CuAssertPtrNotNull (test, key);

	memcpy (key, RSA3K_PRIVKEY_DER, RSA3K_PRIVKEY_DER_LEN);

	ephemeral_key_generation_rsa_testing_init (test, &key_gen_rsa_test);

	/* Set mock expectation */
	status = mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.generate_key,
		&key_gen_rsa_test.rsa, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (key_size));
	status |= mock_expect_save_arg (&key_gen_rsa_test.rsa.mock, 0, 0);

	status |= mock_expect (&key_gen_rsa_test.rsa.mock,
		key_gen_rsa_test.rsa.base.get_private_key_der, &key_gen_rsa_test.rsa, 0,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&length));
	status |= mock_expect_output (&key_gen_rsa_test.rsa.mock, 1, &key, sizeof (key), -1);
	status |= mock_expect_output (&key_gen_rsa_test.rsa.mock, 2, &RSA3K_PRIVKEY_DER_LEN,
		sizeof (RSA3K_PRIVKEY_DER_LEN), -1);

	status |= mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.release_key,
		&key_gen_rsa_test.rsa, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		key_size, key_out, sizeof (key_out), &length);
	CuAssertIntEquals (test, EPHEMERAL_KEY_GEN_SMALL_KEY_BUFFER, status);

	ephemeral_key_generation_rsa_testing_release (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_with_generate_key_failed (CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	size_t key_length = 0;
	uint8_t key_out[4096];
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init (test, &key_gen_rsa_test);

	status = mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.generate_key,
		&key_gen_rsa_test.rsa, RSA_ENGINE_GENERATE_KEY_FAILED, MOCK_ARG_NOT_NULL, MOCK_ARG (2048));
	CuAssertIntEquals (test, 0, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		2048, key_out, sizeof (key_out), &key_length);
	CuAssertIntEquals (test, RSA_ENGINE_GENERATE_KEY_FAILED, status);
	CuAssertIntEquals (test, 0, key_length);

	ephemeral_key_generation_rsa_testing_release (test, &key_gen_rsa_test);
}

static void ephemeral_key_generation_rsa_test_generate_key_with_get_private_key_der_failed (
	CuTest *test)
{
	struct ephemeral_key_generation_rsa_testing key_gen_rsa_test;
	size_t key_length = 0;
	uint8_t key_out[4096];
	int status;

	TEST_START;

	ephemeral_key_generation_rsa_testing_init (test, &key_gen_rsa_test);

	status = mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.generate_key,
		&key_gen_rsa_test.rsa, 0, MOCK_ARG_NOT_NULL, MOCK_ARG (2048));
	status |= mock_expect_save_arg (&key_gen_rsa_test.rsa.mock, 0, 0);

	status |= mock_expect (&key_gen_rsa_test.rsa.mock,
		key_gen_rsa_test.rsa.base.get_private_key_der, &key_gen_rsa_test.rsa, RSA_ENGINE_NO_MEMORY,
		MOCK_ARG_SAVED_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG_PTR (&key_length));

	status |= mock_expect (&key_gen_rsa_test.rsa.mock, key_gen_rsa_test.rsa.base.release_key,
		&key_gen_rsa_test.rsa, 0, MOCK_ARG_SAVED_ARG (0));

	CuAssertIntEquals (test, 0, status);

	status = key_gen_rsa_test.key_gen_rsa.base.generate_key (&key_gen_rsa_test.key_gen_rsa.base,
		2048, key_out, sizeof (key_out), &key_length);
	CuAssertIntEquals (test, RSA_ENGINE_NO_MEMORY, status);
	CuAssertIntEquals (test, 0, key_length);

	ephemeral_key_generation_rsa_testing_release (test, &key_gen_rsa_test);
}


// *INDENT-OFF*
TEST_SUITE_START (ephemeral_key_generation_rsa);

TEST (ephemeral_key_generation_rsa_test_init);
TEST (ephemeral_key_generation_rsa_test_init_null_input);
TEST (ephemeral_key_generation_rsa_test_static_init);
TEST (ephemeral_key_generation_rsa_test_release_null);
TEST (ephemeral_key_generation_rsa_test_generate_key);
TEST (ephemeral_key_generation_rsa_test_generate_key_with_static_init);
TEST (ephemeral_key_generation_rsa_test_generate_key_invalid_input);
TEST (ephemeral_key_generation_rsa_test_generate_key_invalid_key_buffer_size);
TEST (ephemeral_key_generation_rsa_test_generate_key_with_generate_key_failed);
TEST (ephemeral_key_generation_rsa_test_generate_key_with_get_private_key_der_failed);

TEST_SUITE_END;
// *INDENT-ON*
