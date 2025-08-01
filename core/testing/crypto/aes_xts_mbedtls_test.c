// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "testing.h"
#include "crypto/aes_xts_mbedtls.h"
#include "crypto/aes_xts_mbedtls_static.h"
#include "testing/crypto/aes_xts_testing.h"


TEST_SUITE_LABEL ("aes_xts_mbedtls");


/**
 * Dependencies for testing.
 */
struct aes_xts_mbedtls_testing {
	struct aes_xts_engine_mbedtls_state state;	/**< Variable context for the AES-XTS engine. */
	struct aes_xts_engine_mbedtls test;			/**< The engine under test. */
};


/*******************
 * Test cases
 *******************/

static void aes_xts_mbedtls_test_init (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.test.base.set_key);
	CuAssertPtrNotNull (test, engine.test.base.clear_key);
	CuAssertPtrNotNull (test, engine.test.base.encrypt_data);
	CuAssertPtrNotNull (test, engine.test.base.decrypt_data);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_init_null (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_xts_mbedtls_init (NULL, &engine.state);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = aes_xts_mbedtls_init (&engine.test, NULL);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_xts_mbedtls_test_static_init (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine = {
		.test = aes_xts_mbedtls_static_init (&engine.state)
	};
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, engine.test.base.set_key);
	CuAssertPtrNotNull (test, engine.test.base.clear_key);
	CuAssertPtrNotNull (test, engine.test.base.encrypt_data);
	CuAssertPtrNotNull (test, engine.test.base.decrypt_data);

	status = aes_xts_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_static_init_null (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine = {
		.test = aes_xts_mbedtls_static_init (NULL)
	};
	int status;

	TEST_START;

	status = aes_xts_mbedtls_init_state (NULL);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = aes_xts_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_xts_mbedtls_test_release_null (CuTest *test)
{
	TEST_START;

	aes_xts_mbedtls_release (NULL);
}

static void aes_xts_mbedtls_test_encrypt_data_aes128_16bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes128_32bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU32_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU32_KEY,
		AES_XTS_TESTING_KEY128_DU32_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU32_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU32_PLAINTEXT, AES_XTS_TESTING_KEY128_DU32_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU32_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU32_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes128_25bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU25_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU25_KEY,
		AES_XTS_TESTING_KEY128_DU25_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU25_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU25_PLAINTEXT, AES_XTS_TESTING_KEY128_DU25_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU25_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU25_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes128_512bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU512_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU512_KEY,
		AES_XTS_TESTING_KEY128_DU512_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU512_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU512_PLAINTEXT, AES_XTS_TESTING_KEY128_DU512_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU512_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU512_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes128_1024bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU1024_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU1024_KEY,
		AES_XTS_TESTING_KEY128_DU1024_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU1024_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU1024_PLAINTEXT, AES_XTS_TESTING_KEY128_DU1024_DATA_LEN,
		data_unit_id, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU1024_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU1024_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes128_2048bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU2048_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU2048_KEY,
		AES_XTS_TESTING_KEY128_DU2048_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU2048_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU2048_PLAINTEXT, AES_XTS_TESTING_KEY128_DU2048_DATA_LEN,
		data_unit_id, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU2048_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU2048_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes128_4096bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU4096_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU4096_KEY,
		AES_XTS_TESTING_KEY128_DU4096_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU4096_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU4096_PLAINTEXT, AES_XTS_TESTING_KEY128_DU4096_DATA_LEN,
		data_unit_id, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU4096_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU4096_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes256_32bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY256_DU32_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY256_DU32_KEY,
		AES_XTS_TESTING_KEY256_DU32_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY256_DU32_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY256_DU32_PLAINTEXT, AES_XTS_TESTING_KEY256_DU32_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY256_DU32_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY256_DU32_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes256_48bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY256_DU48_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY256_DU48_KEY,
		AES_XTS_TESTING_KEY256_DU48_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY256_DU48_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY256_DU48_PLAINTEXT, AES_XTS_TESTING_KEY256_DU48_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY256_DU48_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY256_DU48_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_aes256_512bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY256_DU512_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY256_DU512_KEY,
		AES_XTS_TESTING_KEY256_DU512_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY256_DU512_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY256_DU512_PLAINTEXT, AES_XTS_TESTING_KEY256_DU512_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY256_DU512_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY256_DU512_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_same_buffer (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	memcpy (ciphertext, AES_XTS_TESTING_KEY128_DU16_PLAINTEXT,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN);

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base, ciphertext,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_static_init (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine = {
		.test = aes_xts_mbedtls_static_init (&engine.state)
	};
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, ciphertext,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_null (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (NULL, AES_XTS_TESTING_KEY128_DU16_PLAINTEXT,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.encrypt_data (&engine.test.base, NULL,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, NULL,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		NULL, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_small_buffer (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		ciphertext, AES_XTS_TESTING_KEY128_DU16_DATA_LEN - 1);
	CuAssertIntEquals (test, AES_XTS_ENGINE_OUT_BUFFER_TOO_SMALL, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_length_too_short (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN - 1,
		data_unit_id, ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_DATA_LENGTH, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_length_too_long (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];
	size_t bad_length = ((1U << 20) * 16) + 1;

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	/* At most 2^20 blocks are allowed (2^20 * 16 bytes). */
	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, bad_length, data_unit_id, ciphertext, bad_length);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_DATA_LENGTH, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_data_no_key (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_NO_KEY, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_set_key_null (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (NULL, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.set_key (&engine.test.base, NULL,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_set_key_bad_length (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		(128 / 8));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_KEY_LENGTH, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_set_key_matching_keys (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t key[AES_XTS_TESTING_KEY128_DU16_KEY_LEN];

	TEST_START;

	memcpy (key, AES_XTS_TESTING_KEY128_DU16_KEY, AES_XTS_TESTING_KEY128_DU16_KEY_LEN / 2);
	memcpy (&key[AES_XTS_TESTING_KEY128_DU16_KEY_LEN / 2], AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN / 2);

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, key, sizeof (key));
	CuAssertIntEquals (test, AES_XTS_ENGINE_MATCHING_KEYS, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes128_16bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes128_32bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU32_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU32_KEY,
		AES_XTS_TESTING_KEY128_DU32_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU32_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU32_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU32_DATA_LEN, data_unit_id,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU32_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU32_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes128_25bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU25_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU25_KEY,
		AES_XTS_TESTING_KEY128_DU25_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU25_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU25_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU25_DATA_LEN, data_unit_id,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU25_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU25_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes128_512bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU512_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU512_KEY,
		AES_XTS_TESTING_KEY128_DU512_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU512_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU512_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU512_DATA_LEN,
		data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU512_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU512_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes128_1024bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU1024_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU1024_KEY,
		AES_XTS_TESTING_KEY128_DU1024_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU1024_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU1024_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU1024_DATA_LEN,
		data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU1024_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU1024_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes128_2048bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU2048_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU2048_KEY,
		AES_XTS_TESTING_KEY128_DU2048_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU2048_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU2048_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU2048_DATA_LEN,
		data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU2048_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU2048_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes128_4096bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU4096_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU4096_KEY,
		AES_XTS_TESTING_KEY128_DU4096_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU4096_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU4096_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU4096_DATA_LEN,
		data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU4096_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU4096_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes256_32bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY256_DU32_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY256_DU32_KEY,
		AES_XTS_TESTING_KEY256_DU32_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY256_DU32_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY256_DU32_CIPHERTEXT, AES_XTS_TESTING_KEY256_DU32_DATA_LEN, data_unit_id,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY256_DU32_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY256_DU32_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes256_48bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY256_DU48_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY256_DU48_KEY,
		AES_XTS_TESTING_KEY256_DU48_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY256_DU48_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY256_DU48_CIPHERTEXT, AES_XTS_TESTING_KEY256_DU48_DATA_LEN, data_unit_id,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY256_DU48_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY256_DU48_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_aes256_512bytes (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY256_DU512_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY256_DU512_KEY,
		AES_XTS_TESTING_KEY256_DU512_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY256_DU512_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY256_DU512_CIPHERTEXT, AES_XTS_TESTING_KEY256_DU512_DATA_LEN,
		data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY256_DU512_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY256_DU512_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_same_buffer (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	memcpy (plaintext, AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN);

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base, plaintext,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_static_init (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine = {
		.test = aes_xts_mbedtls_static_init (&engine.state)
	};
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_null (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.decrypt_data (NULL, AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.decrypt_data (&engine.test.base, NULL,
		AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, NULL,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		NULL, sizeof (plaintext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_small_buffer (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		plaintext, AES_XTS_TESTING_KEY128_DU16_DATA_LEN - 1);
	CuAssertIntEquals (test, AES_XTS_ENGINE_OUT_BUFFER_TOO_SMALL, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_length_too_short (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN - 1,
		data_unit_id, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_DATA_LENGTH, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_length_too_long (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];
	size_t bad_length = ((1U << 20) * 16) + 1;

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	/* At most 2^20 blocks are allowed (2^20 * 16 bytes). */
	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, bad_length, data_unit_id, plaintext, bad_length);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_DATA_LENGTH, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_decrypt_data_no_key (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_NO_KEY, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_and_decrypt_aes128 (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU512_DATA_LEN];
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU512_DATA_LEN];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU512_PLAINTEXT, AES_XTS_TESTING_KEY128_DU512_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base, ciphertext, sizeof (ciphertext),
		data_unit_id, (uint8_t*) plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU512_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY128_DU512_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_and_decrypt_aes256 (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY256_DU512_DATA_LEN];
	uint8_t plaintext[AES_XTS_TESTING_KEY256_DU512_DATA_LEN];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY256_DU32_KEY,
		AES_XTS_TESTING_KEY256_DU32_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY256_DU32_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY256_DU512_PLAINTEXT, AES_XTS_TESTING_KEY256_DU512_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base, ciphertext, sizeof (ciphertext),
		data_unit_id, (uint8_t*) plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY256_DU512_PLAINTEXT, plaintext,
		AES_XTS_TESTING_KEY256_DU512_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_encrypt_with_different_keys (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext1[AES_XTS_TESTING_KEY128_DU512_DATA_LEN];
	uint8_t plaintext1[AES_XTS_TESTING_KEY128_DU512_DATA_LEN];
	uint8_t ciphertext2[AES_XTS_TESTING_KEY128_DU512_DATA_LEN];
	uint8_t plaintext2[AES_XTS_TESTING_KEY128_DU512_DATA_LEN];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU32_KEY,
		AES_XTS_TESTING_KEY128_DU32_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU32_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU512_PLAINTEXT, AES_XTS_TESTING_KEY128_DU512_DATA_LEN, data_unit_id,
		ciphertext1, sizeof (ciphertext1));
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base, ciphertext1, sizeof (ciphertext1),
		data_unit_id, (uint8_t*) plaintext1, sizeof (plaintext1));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU512_PLAINTEXT, plaintext1,
		AES_XTS_TESTING_KEY128_DU512_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU25_KEY,
		AES_XTS_TESTING_KEY128_DU25_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU512_PLAINTEXT, AES_XTS_TESTING_KEY128_DU512_DATA_LEN, data_unit_id,
		ciphertext2, sizeof (ciphertext2));
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.decrypt_data (&engine.test.base, ciphertext2, sizeof (ciphertext2),
		data_unit_id, (uint8_t*) plaintext2, sizeof (plaintext2));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_XTS_TESTING_KEY128_DU512_PLAINTEXT, plaintext2,
		AES_XTS_TESTING_KEY128_DU512_DATA_LEN);
	CuAssertIntEquals (test, 0, status);

	status = memcmp (ciphertext1, ciphertext2, sizeof (ciphertext1));
	CuAssertTrue (test, (status != 0));

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_clear_key_encrypt (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.clear_key (&engine.test.base);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_NO_KEY, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_clear_key_decrypt (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;
	uint8_t plaintext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.clear_key (&engine.test.base);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.decrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_CIPHERTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_NO_KEY, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_clear_key_static_init (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine = {
		.test = aes_xts_mbedtls_static_init (&engine.state)
	};
	int status;
	uint8_t ciphertext[AES_XTS_TESTING_KEY128_DU16_DATA_LEN * 2];
	uint8_t data_unit_id[16];

	TEST_START;

	status = aes_xts_mbedtls_init_state (&engine.test);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.set_key (&engine.test.base, AES_XTS_TESTING_KEY128_DU16_KEY,
		AES_XTS_TESTING_KEY128_DU16_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.clear_key (&engine.test.base);
	CuAssertIntEquals (test, 0, status);

	aes_xts_flash_address_to_data_unit_id (AES_XTS_TESTING_KEY128_DU16_ID, data_unit_id);

	status = engine.test.base.encrypt_data (&engine.test.base,
		AES_XTS_TESTING_KEY128_DU16_PLAINTEXT, AES_XTS_TESTING_KEY128_DU16_DATA_LEN, data_unit_id,
		ciphertext, sizeof (ciphertext));
	CuAssertIntEquals (test, AES_XTS_ENGINE_NO_KEY, status);

	aes_xts_mbedtls_release (&engine.test);
}

static void aes_xts_mbedtls_test_clear_key_null (CuTest *test)
{
	struct aes_xts_mbedtls_testing engine;
	int status;

	TEST_START;

	status = aes_xts_mbedtls_init (&engine.test, &engine.state);
	CuAssertIntEquals (test, 0, status);

	status = engine.test.base.clear_key (NULL);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);

	aes_xts_mbedtls_release (&engine.test);
}


// *INDENT-OFF*
TEST_SUITE_START (aes_xts_mbedtls);

TEST (aes_xts_mbedtls_test_init);
TEST (aes_xts_mbedtls_test_init_null);
TEST (aes_xts_mbedtls_test_static_init);
TEST (aes_xts_mbedtls_test_static_init_null);
TEST (aes_xts_mbedtls_test_release_null);
TEST (aes_xts_mbedtls_test_encrypt_data_aes128_16bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes128_32bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes128_25bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes128_512bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes128_1024bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes128_2048bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes128_4096bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes256_32bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes256_48bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_aes256_512bytes);
TEST (aes_xts_mbedtls_test_encrypt_data_same_buffer);
TEST (aes_xts_mbedtls_test_encrypt_data_static_init);
TEST (aes_xts_mbedtls_test_encrypt_data_null);
TEST (aes_xts_mbedtls_test_encrypt_data_small_buffer);
TEST (aes_xts_mbedtls_test_encrypt_data_length_too_short);
TEST (aes_xts_mbedtls_test_encrypt_data_length_too_long);
TEST (aes_xts_mbedtls_test_encrypt_data_no_key);
TEST (aes_xts_mbedtls_test_set_key_null);
TEST (aes_xts_mbedtls_test_set_key_bad_length);
TEST (aes_xts_mbedtls_test_set_key_matching_keys);
TEST (aes_xts_mbedtls_test_decrypt_data_aes128_16bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes128_32bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes128_25bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes128_512bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes128_1024bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes128_2048bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes128_4096bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes256_32bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes256_48bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_aes256_512bytes);
TEST (aes_xts_mbedtls_test_decrypt_data_same_buffer);
TEST (aes_xts_mbedtls_test_decrypt_data_static_init);
TEST (aes_xts_mbedtls_test_decrypt_data_null);
TEST (aes_xts_mbedtls_test_decrypt_data_small_buffer);
TEST (aes_xts_mbedtls_test_decrypt_data_length_too_short);
TEST (aes_xts_mbedtls_test_decrypt_data_length_too_long);
TEST (aes_xts_mbedtls_test_decrypt_data_no_key);
TEST (aes_xts_mbedtls_test_encrypt_and_decrypt_aes128);
TEST (aes_xts_mbedtls_test_encrypt_and_decrypt_aes256);
TEST (aes_xts_mbedtls_test_encrypt_with_different_keys);
TEST (aes_xts_mbedtls_test_clear_key_encrypt);
TEST (aes_xts_mbedtls_test_clear_key_decrypt);
TEST (aes_xts_mbedtls_test_clear_key_static_init);
TEST (aes_xts_mbedtls_test_clear_key_null);

TEST_SUITE_END;
// *INDENT-ON*
