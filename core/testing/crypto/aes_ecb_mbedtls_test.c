// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "testing.h"
#include "crypto/aes_ecb_mbedtls.h"
#include "crypto/aes_ecb_mbedtls_static.h"
#include "testing/crypto/aes_ecb_testing.h"


TEST_SUITE_LABEL ("aes_ecb_mbedtls");


/**
 * Dependencies for testing.
 */
struct aes_ecb_mbedtls_testing {
	struct aes_ecb_engine_mbedtls_state state;	/**< Variable context for the AES-ECB engine. */
	struct aes_ecb_engine_mbedtls test;			/**< The engine under test. */
};


/*******************
 * Test cases
 *******************/

static void aes_ecb_mbedtls_test_init (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.test.base.set_key);
	CuAssertPtrNotNull (test, engine.test.base.clear_key);
	CuAssertPtrNotNull (test, engine.test.base.encrypt_data);
	CuAssertPtrNotNull (test, engine.test.base.decrypt_data);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_init_null (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_ecb_mbedtls_init (NULL, &engine.state);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	status = aes_ecb_mbedtls_init (&engine.test, NULL);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_ecb_mbedtls_test_static_init (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine = {
		.test = aes_ecb_mbedtls_static_init (&engine.state)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, engine.test.base.set_key);
	CuAssertPtrNotNull (test, engine.test.base.clear_key);
	CuAssertPtrNotNull (test, engine.test.base.encrypt_data);
	CuAssertPtrNotNull (test, engine.test.base.decrypt_data);

	status = aes_ecb_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_static_init_null (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine = {
		.test = aes_ecb_mbedtls_static_init (NULL)
	};
	int status;

	TEST_START;

	status = aes_ecb_mbedtls_init_state (NULL);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	status = aes_ecb_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_ecb_mbedtls_test_release_null (CuTest *test)
{
	TEST_START;

	aes_ecb_mbedtls_release (NULL);
}

static void aes_ecb_mbedtls_test_encrypt_data_single_block (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext,
		sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT, ciphertext,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_data_multi_block (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_MULTI_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_MULTI_BLOCK_KEY,
		AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_MULTI_BLOCK_PLAINTEXT, AES_ECB_TESTING_MULTI_BLOCK_LEN, ciphertext,
		sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_MULTI_BLOCK_CIPHERTEXT, ciphertext,
		AES_ECB_TESTING_MULTI_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_data_same_buffer (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_LONG_DATA_LEN * 2];

	TEST_START;

	memcpy (ciphertext, AES_ECB_TESTING_LONG_DATA_PLAINTEXT, AES_ECB_TESTING_LONG_DATA_LEN);

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_LONG_DATA_KEY,
		AES_ECB_TESTING_LONG_DATA_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base, ciphertext,
		AES_ECB_TESTING_LONG_DATA_LEN, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_LONG_DATA_CIPHERTEXT, ciphertext,
		AES_ECB_TESTING_LONG_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_data_static_init (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine = {
		.test = aes_ecb_mbedtls_static_init (&engine.state)
	};
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext,
		sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT, ciphertext,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_data_null (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (NULL, AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.encrypt_data (&engine.test.base, NULL,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, NULL,
		sizeof (ciphertext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_data_small_buffer (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_MULTI_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_MULTI_BLOCK_KEY,
		AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_MULTI_BLOCK_PLAINTEXT, AES_ECB_TESTING_MULTI_BLOCK_LEN, ciphertext,
		AES_ECB_TESTING_MULTI_BLOCK_LEN - AES_ECB_BLOCK_SIZE);
	CuAssertIntEquals (test, AES_ECB_ENGINE_OUT_BUFFER_TOO_SMALL, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_data_not_block_aligned (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_MULTI_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_MULTI_BLOCK_KEY,
		AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_MULTI_BLOCK_PLAINTEXT, AES_ECB_TESTING_MULTI_BLOCK_LEN - 1, ciphertext,
		sizeof (ciphertext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_DATA_LENGTH, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_data_zero_length (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, 0, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_DATA_LENGTH, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_data_no_key (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext,
		sizeof (ciphertext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_set_key_null (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (NULL, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.set_key (&engine.test.base, NULL,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_set_key_bad_length (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN - 1);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_KEY_LENGTH, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_set_key_unsupported_length (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		(128 / 8));
	CuAssertIntEquals (test, AES_ECB_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		(192 / 8));
	CuAssertIntEquals (test, AES_ECB_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_single_block (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, plaintext,
		sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, plaintext,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_multi_block (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_MULTI_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_MULTI_BLOCK_KEY,
		AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_MULTI_BLOCK_CIPHERTEXT, AES_ECB_TESTING_MULTI_BLOCK_LEN, plaintext,
		sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_MULTI_BLOCK_PLAINTEXT, plaintext,
		AES_ECB_TESTING_MULTI_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_same_buffer (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_LONG_DATA_LEN * 2];

	TEST_START;

	memcpy (plaintext, AES_ECB_TESTING_LONG_DATA_CIPHERTEXT, AES_ECB_TESTING_LONG_DATA_LEN);

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_LONG_DATA_KEY,
		AES_ECB_TESTING_LONG_DATA_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base, plaintext,
		AES_ECB_TESTING_LONG_DATA_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_LONG_DATA_PLAINTEXT, plaintext,
		AES_ECB_TESTING_LONG_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_static_init (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine = {
		.test = aes_ecb_mbedtls_static_init (&engine.state)
	};
	int status;
	uint8_t plaintext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, plaintext,
		sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, plaintext,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_null (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (NULL, AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.decrypt_data (&engine.test.base, NULL,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, NULL,
		sizeof (plaintext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_small_buffer (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_MULTI_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_MULTI_BLOCK_KEY,
		AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_MULTI_BLOCK_CIPHERTEXT, AES_ECB_TESTING_MULTI_BLOCK_LEN, plaintext,
		AES_ECB_TESTING_MULTI_BLOCK_LEN - AES_ECB_BLOCK_SIZE);
	CuAssertIntEquals (test, AES_ECB_ENGINE_OUT_BUFFER_TOO_SMALL, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_not_block_aligned (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_MULTI_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_MULTI_BLOCK_KEY,
		AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_MULTI_BLOCK_CIPHERTEXT, AES_ECB_TESTING_MULTI_BLOCK_LEN - 1, plaintext,
		sizeof (plaintext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_DATA_LENGTH, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_zero_length (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT, 0, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_DATA_LENGTH, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_decrypt_data_no_key (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, plaintext,
		sizeof (plaintext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_and_decrypt (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_LONG_DATA_LEN];
	uint8_t plaintext[AES_ECB_TESTING_LONG_DATA_LEN];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_LONG_DATA_KEY,
		AES_ECB_TESTING_LONG_DATA_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base, AES_ECB_TESTING_LONG_DATA_PLAINTEXT,
		AES_ECB_TESTING_LONG_DATA_LEN, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base, ciphertext, sizeof (ciphertext),
		(uint8_t*) plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_LONG_DATA_PLAINTEXT, plaintext,
		AES_ECB_TESTING_LONG_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_encrypt_with_different_keys (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext1[AES_ECB_TESTING_SINGLE_BLOCK_LEN];
	uint8_t plaintext1[AES_ECB_TESTING_SINGLE_BLOCK_LEN];
	uint8_t ciphertext2[AES_ECB_TESTING_SINGLE_BLOCK_LEN];
	uint8_t plaintext2[AES_ECB_TESTING_SINGLE_BLOCK_LEN];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext1,
		sizeof (ciphertext1));
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base, ciphertext1, sizeof (ciphertext1),
		(uint8_t*) plaintext1, sizeof (plaintext1));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, plaintext1,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_MULTI_BLOCK_KEY,
		AES_ECB_TESTING_MULTI_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext2,
		sizeof (ciphertext2));
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base, ciphertext2, sizeof (ciphertext2),
		(uint8_t*) plaintext2, sizeof (plaintext2));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, plaintext2,
		AES_ECB_TESTING_SINGLE_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	status = memcmp (ciphertext1, ciphertext2, sizeof (ciphertext1));
	CuAssertTrue (test, (status != 0));

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_clear_key_encrypt (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.clear_key (&engine.test.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext,
		sizeof (ciphertext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_clear_key_decrypt (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.clear_key (&engine.test.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_CIPHERTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, plaintext,
		sizeof (plaintext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_clear_key_static_init (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine = {
		.test = aes_ecb_mbedtls_static_init (&engine.state)
	};
	int status;
	uint8_t ciphertext[AES_ECB_TESTING_SINGLE_BLOCK_LEN * 2];

	TEST_START;

	status = aes_ecb_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_ECB_TESTING_SINGLE_BLOCK_KEY,
		AES_ECB_TESTING_SINGLE_BLOCK_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.clear_key (&engine.test.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_ECB_TESTING_SINGLE_BLOCK_PLAINTEXT, AES_ECB_TESTING_SINGLE_BLOCK_LEN, ciphertext,
		sizeof (ciphertext));
	CuAssertIntEquals (test, AES_ECB_ENGINE_NO_KEY, status);

	aes_ecb_mbedtls_release (&engine.test);
}

static void aes_ecb_mbedtls_test_clear_key_null (CuTest *test)
{
	struct aes_ecb_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_ecb_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.clear_key (NULL);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);

	aes_ecb_mbedtls_release (&engine.test);
}


// *INDENT-OFF*
TEST_SUITE_START (aes_ecb_mbedtls);

TEST (aes_ecb_mbedtls_test_init);
TEST (aes_ecb_mbedtls_test_init_null);
TEST (aes_ecb_mbedtls_test_static_init);
TEST (aes_ecb_mbedtls_test_static_init_null);
TEST (aes_ecb_mbedtls_test_release_null);
TEST (aes_ecb_mbedtls_test_encrypt_data_single_block);
TEST (aes_ecb_mbedtls_test_encrypt_data_multi_block);
TEST (aes_ecb_mbedtls_test_encrypt_data_same_buffer);
TEST (aes_ecb_mbedtls_test_encrypt_data_static_init);
TEST (aes_ecb_mbedtls_test_encrypt_data_null);
TEST (aes_ecb_mbedtls_test_encrypt_data_small_buffer);
TEST (aes_ecb_mbedtls_test_encrypt_data_not_block_aligned);
TEST (aes_ecb_mbedtls_test_encrypt_data_zero_length);
TEST (aes_ecb_mbedtls_test_encrypt_data_no_key);
TEST (aes_ecb_mbedtls_test_set_key_null);
TEST (aes_ecb_mbedtls_test_set_key_bad_length);
TEST (aes_ecb_mbedtls_test_set_key_unsupported_length);
TEST (aes_ecb_mbedtls_test_decrypt_data_single_block);
TEST (aes_ecb_mbedtls_test_decrypt_data_multi_block);
TEST (aes_ecb_mbedtls_test_decrypt_data_same_buffer);
TEST (aes_ecb_mbedtls_test_decrypt_data_static_init);
TEST (aes_ecb_mbedtls_test_decrypt_data_null);
TEST (aes_ecb_mbedtls_test_decrypt_data_small_buffer);
TEST (aes_ecb_mbedtls_test_decrypt_data_not_block_aligned);
TEST (aes_ecb_mbedtls_test_decrypt_data_zero_length);
TEST (aes_ecb_mbedtls_test_decrypt_data_no_key);
TEST (aes_ecb_mbedtls_test_encrypt_and_decrypt);
TEST (aes_ecb_mbedtls_test_encrypt_with_different_keys);
TEST (aes_ecb_mbedtls_test_clear_key_encrypt);
TEST (aes_ecb_mbedtls_test_clear_key_decrypt);
TEST (aes_ecb_mbedtls_test_clear_key_static_init);
TEST (aes_ecb_mbedtls_test_clear_key_null);

TEST_SUITE_END;
// *INDENT-ON*
