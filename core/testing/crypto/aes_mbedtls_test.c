// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "platform.h"
#include "testing.h"
#include "crypto/aes_mbedtls.h"
#include "testing/crypto/aes_testing.h"


TEST_SUITE_LABEL ("aes_mbedtls");


/*******************
 * Test cases
 *******************/

static void aes_mbedtls_test_init (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.set_key);
	CuAssertPtrNotNull (test, engine.base.encrypt_data);
	CuAssertPtrNotNull (test, engine.base.decrypt_data);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_mbedtls_init (NULL);
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_mbedtls_test_release_null (CuTest *test)
{
	TEST_START;

	aes_mbedtls_release (NULL);
}

static void aes_mbedtls_test_encrypt_data (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t ciphertext[AES_CIPHERTEXT_LEN * 2];
	uint8_t tag[AES_GCM_TAG_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_CIPHERTEXT, ciphertext, AES_PLAINTEXT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_GCM_TAG, tag, AES_GCM_TAG_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_mbedtls_release (&engine);
}

/* TODO: mbedTLS doesn't support GCM operations without a tag. */
//static void aes_mbedtls_test_encrypt_data_no_tag (CuTest *test)
//{
//	struct aes_engine_mbedtls engine;
//	int status;
//	uint8_t ciphertext[AES_CIPHERTEXT_LEN * 2];
//
//	TEST_START;
//
//	status = aes_mbedtls_init (&engine);
//	CuAssertIntEquals (test, 0, status);
//
//	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
//	CuAssertIntEquals (test, 0, status);
//
//	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
//		AES_IV_LEN, ciphertext, sizeof (ciphertext), NULL, 0);
//	CuAssertIntEquals (test, 0, status);
//
//	status = testing_validate_array (AES_CIPHERTEXT, ciphertext, AES_PLAINTEXT_LEN);
//	CuAssertIntEquals (test, 0, status);
//
//	aes_mbedtls_release (&engine);
//}

static void aes_mbedtls_test_encrypt_data_same_buffer (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t ciphertext[AES_CIPHERTEXT_LEN * 2];
	uint8_t tag[AES_GCM_TAG_LEN * 2];

	TEST_START;

	memcpy (ciphertext, AES_PLAINTEXT, AES_PLAINTEXT_LEN);

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, ciphertext, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_CIPHERTEXT, ciphertext, AES_PLAINTEXT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_GCM_TAG, tag, AES_GCM_TAG_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_encrypt_data_null (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t ciphertext[AES_CIPHERTEXT_LEN * 2];
	uint8_t tag[AES_GCM_TAG_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (NULL, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.encrypt_data (&engine.base, NULL, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, 0, AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, NULL,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
		0, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, NULL, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), NULL, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_encrypt_data_small_buffer (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t ciphertext[AES_CIPHERTEXT_LEN * 2];
	uint8_t tag[AES_GCM_TAG_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, ciphertext, AES_PLAINTEXT_LEN - 1, tag, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_OUT_BUFFER_TOO_SMALL, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_encrypt_data_small_tag_buffer (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t ciphertext[AES_CIPHERTEXT_LEN * 2];
	uint8_t tag[AES_GCM_TAG_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, AES_GCM_TAG_LEN - 1);
	CuAssertIntEquals (test, AES_ENGINE_OUT_BUFFER_TOO_SMALL, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_encrypt_data_no_key (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t ciphertext[AES_CIPHERTEXT_LEN * 2];
	uint8_t tag[AES_GCM_TAG_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, AES_PLAINTEXT, AES_PLAINTEXT_LEN, AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, AES_ENGINE_NO_KEY, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_set_key_null (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (NULL, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.set_key (&engine.base, NULL, AES_KEY_LEN);
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_set_key_bad_length (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, 3);
	CuAssertIntEquals (test, AES_ENGINE_INVALID_KEY_LENGTH, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_set_key_unsupported_length (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, (128 / 8));
	CuAssertIntEquals (test, AES_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	status = engine.base.set_key (&engine.base, AES_KEY, (192 / 8));
	CuAssertIntEquals (test, AES_ENGINE_UNSUPPORTED_KEY_LENGTH, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_decrypt_data (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t plaintext[AES_PLAINTEXT_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_PLAINTEXT, plaintext, AES_CIPHERTEXT_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_mbedtls_release (&engine);
}

/* TODO: mbedTLS doesn't support GCM operations without a tag. */
//static void aes_mbedtls_test_decrypt_data_no_tag (CuTest *test)
//{
//	struct aes_engine_mbedtls engine;
//	int status;
//	uint8_t plaintext[AES_PLAINTEXT_LEN * 2];
//
//	TEST_START;
//
//	status = aes_mbedtls_init (&engine);
//	CuAssertIntEquals (test, 0, status);
//
//	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
//	CuAssertIntEquals (test, 0, status);
//
//	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
//		NULL, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
//	CuAssertIntEquals (test, 0, status);
//
//	status = testing_validate_array (AES_PLAINTEXT, plaintext, AES_CIPHERTEXT_LEN);
//	CuAssertIntEquals (test, 0, status);
//
//	aes_mbedtls_release (&engine);
//}

static void aes_mbedtls_test_decrypt_data_same_buffer (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t plaintext[AES_PLAINTEXT_LEN * 2];

	TEST_START;

	memcpy (plaintext, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN);

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, plaintext, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (AES_PLAINTEXT, plaintext, AES_CIPHERTEXT_LEN);
	CuAssertIntEquals (test, 0, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_decrypt_data_null (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t plaintext[AES_PLAINTEXT_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (NULL, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt_data (&engine.base, NULL, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, 0,
		AES_GCM_TAG, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		NULL, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, NULL, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, AES_IV, 0, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, AES_IV, AES_IV_LEN, NULL, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_INVALID_ARGUMENT, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_decrypt_data_small_buffer (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t plaintext[AES_PLAINTEXT_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, AES_IV, AES_IV_LEN, plaintext, AES_CIPHERTEXT_LEN - 1);
	CuAssertIntEquals (test, AES_ENGINE_OUT_BUFFER_TOO_SMALL, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_decrypt_data_no_key (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t plaintext[AES_PLAINTEXT_LEN * 2];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		AES_GCM_TAG, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_NO_KEY, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_decrypt_data_bad_tag (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t plaintext[AES_PLAINTEXT_LEN * 2];
	uint8_t bad_tag[AES_GCM_TAG_LEN];

	TEST_START;

	memcpy (bad_tag, AES_GCM_TAG, AES_GCM_TAG_LEN);
	bad_tag[0] ^= 0x55;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN,
		bad_tag, AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_GCM_AUTH_FAILED, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_decrypt_data_bad_data (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	uint8_t plaintext[AES_PLAINTEXT_LEN * 2];
	uint8_t bad_data[AES_CIPHERTEXT_LEN];

	TEST_START;

	memcpy (bad_data, AES_CIPHERTEXT, AES_CIPHERTEXT_LEN);
	bad_data[0] ^= 0x55;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, bad_data, sizeof (bad_data), AES_GCM_TAG,
		AES_IV, AES_IV_LEN, plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, AES_ENGINE_GCM_AUTH_FAILED, status);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_encrypt_and_decrypt (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	const char *message = "Test";
	uint8_t ciphertext[strlen (message)];
	uint8_t tag[AES_GCM_TAG_LEN];
	char plaintext[strlen (message) + 1];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, (uint8_t*) message, strlen (message), AES_IV,
		AES_IV_LEN, ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, ciphertext, sizeof (ciphertext), tag, AES_IV,
		AES_IV_LEN, (uint8_t*) plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	plaintext[strlen (message)] = '\0';
	CuAssertStrEquals (test, message, plaintext);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_encrypt_with_longer_iv (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	const char *message = "Test";
	const uint8_t iv[] = {
		0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f
	};
	uint8_t ciphertext[strlen (message)];
	uint8_t tag[AES_GCM_TAG_LEN];
	char plaintext[strlen (message) + 1];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, (uint8_t*) message, strlen (message), iv,
		sizeof (iv), ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, ciphertext, sizeof (ciphertext), tag, iv,
		sizeof (iv), (uint8_t*) plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	plaintext[strlen (message)] = '\0';
	CuAssertStrEquals (test, message, plaintext);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_encrypt_with_shorter_iv (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	const char *message = "Test";
	const uint8_t iv[] = {
		0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47
	};
	uint8_t ciphertext[strlen (message)];
	uint8_t tag[AES_GCM_TAG_LEN];
	char plaintext[strlen (message) + 1];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, (uint8_t*) message, strlen (message), iv,
		sizeof (iv), ciphertext, sizeof (ciphertext), tag, sizeof (tag));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, ciphertext, sizeof (ciphertext), tag, iv,
		sizeof (iv), (uint8_t*) plaintext, sizeof (plaintext));
	CuAssertIntEquals (test, 0, status);

	plaintext[strlen (message)] = '\0';
	CuAssertStrEquals (test, message, plaintext);

	aes_mbedtls_release (&engine);
}

static void aes_mbedtls_test_encrypt_with_different_keys (CuTest *test)
{
	struct aes_engine_mbedtls engine;
	int status;
	const char *message = "Test";
	const uint8_t key2[] = {
		0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c,0x8d,0x8e,0x8f,
		0x90,0x91,0x92,0x93,0x94,0x95,0x96,0x97,0x98,0x99,0x9a,0x9b,0x9c,0x9d,0x9e,0x9f
	};
	uint8_t ciphertext1[strlen (message)];
	uint8_t tag1[AES_GCM_TAG_LEN];
	char plaintext1[strlen (message) + 1];
	uint8_t ciphertext2[strlen (message)];
	uint8_t tag2[AES_GCM_TAG_LEN];
	char plaintext2[strlen (message) + 1];

	TEST_START;

	status = aes_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.set_key (&engine.base, AES_KEY, AES_KEY_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, (uint8_t*) message, strlen (message), AES_IV,
		AES_IV_LEN, ciphertext1, sizeof (ciphertext1), tag1, sizeof (tag1));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, ciphertext1, sizeof (ciphertext1), tag1,
		AES_IV, AES_IV_LEN, (uint8_t*) plaintext1, sizeof (plaintext1));
	CuAssertIntEquals (test, 0, status);

	plaintext1[strlen (message)] = '\0';
	CuAssertStrEquals (test, message, plaintext1);

	status = engine.base.set_key (&engine.base, key2, sizeof (key2));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encrypt_data (&engine.base, (uint8_t*) message, strlen (message), AES_IV,
		AES_IV_LEN, ciphertext2, sizeof (ciphertext2), tag2, sizeof (tag2));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.decrypt_data (&engine.base, ciphertext2, sizeof (ciphertext2), tag2,
		AES_IV, AES_IV_LEN, (uint8_t*) plaintext2, sizeof (plaintext2));
	CuAssertIntEquals (test, 0, status);

	plaintext2[strlen (message)] = '\0';
	CuAssertStrEquals (test, message, plaintext2);

	status = testing_validate_array (ciphertext1, ciphertext2, sizeof (ciphertext1));
	CuAssertTrue (test, (status != 0));

	aes_mbedtls_release (&engine);
}


TEST_SUITE_START (aes_mbedtls);

TEST (aes_mbedtls_test_init);
TEST (aes_mbedtls_test_init_null);
TEST (aes_mbedtls_test_release_null);
TEST (aes_mbedtls_test_encrypt_data);
// TEST (aes_mbedtls_test_encrypt_data_no_tag);
TEST (aes_mbedtls_test_encrypt_data_same_buffer);
TEST (aes_mbedtls_test_encrypt_data_null);
TEST (aes_mbedtls_test_encrypt_data_small_buffer);
TEST (aes_mbedtls_test_encrypt_data_small_tag_buffer);
TEST (aes_mbedtls_test_encrypt_data_no_key);
TEST (aes_mbedtls_test_set_key_null);
TEST (aes_mbedtls_test_set_key_bad_length);
TEST (aes_mbedtls_test_set_key_unsupported_length);
TEST (aes_mbedtls_test_decrypt_data);
// TEST (aes_mbedtls_test_decrypt_data_no_tag);
TEST (aes_mbedtls_test_decrypt_data_same_buffer);
TEST (aes_mbedtls_test_decrypt_data_null);
TEST (aes_mbedtls_test_decrypt_data_small_buffer);
TEST (aes_mbedtls_test_decrypt_data_no_key);
TEST (aes_mbedtls_test_decrypt_data_bad_tag);
TEST (aes_mbedtls_test_decrypt_data_bad_data);
TEST (aes_mbedtls_test_encrypt_and_decrypt);
TEST (aes_mbedtls_test_encrypt_with_longer_iv);
TEST (aes_mbedtls_test_encrypt_with_shorter_iv);
TEST (aes_mbedtls_test_encrypt_with_different_keys);

TEST_SUITE_END;
