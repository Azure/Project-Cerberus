// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/kat/aes_kat.h"
#include "crypto/kat/aes_kat_vectors.h"
#include "testing/engines/aes_testing_engine.h"
#include "testing/mock/crypto/aes_cbc_mock.h"
#include "testing/mock/crypto/aes_ecb_mock.h"
#include "testing/mock/crypto/aes_gcm_mock.h"
#include "testing/mock/crypto/aes_xts_mock.h"


TEST_SUITE_LABEL ("aes_kat");

/*******************
 * Test cases
 *******************/

static void aes_gcm_kat_test_self_test_encrypt_aes256 (CuTest *test)
{
	int status;

	AES_GCM_TESTING_ENGINE (aes_gcm);

	TEST_START;

	status = AES_GCM_TESTING_ENGINE_INIT (&aes_gcm);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_encrypt_aes256 (&aes_gcm.base);
	CuAssertIntEquals (test, 0, status);

	AES_GCM_TESTING_ENGINE_RELEASE (&aes_gcm);
}

static void aes_gcm_kat_test_self_test_encrypt_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_gcm_kat_run_self_test_encrypt_aes256 (NULL);
	CuAssertIntEquals (test, AES_GCM_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_gcm_kat_test_self_test_encrypt_aes256_set_key_fail (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base,
		AES_GCM_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY),
		MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_SET_KEY_FAILED, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_gcm_kat_test_self_test_encrypt_aes256_encrypt_data_fail (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY), MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base,
		AES_GCM_ENGINE_ENCRYPT_FAILED, MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_PLAINTEXT),
		MOCK_ARG (AES_GCM_KAT_VECTORS_PLAINTEXT_LEN), MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_IV),
		MOCK_ARG (AES_GCM_KAT_VECTORS_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_KAT_VECTORS_TAG_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_ENCRYPT_FAILED, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_gcm_kat_test_self_test_encrypt_aes256_unexpected_cipher (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;
	uint8_t cipher[AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN] = {};

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY), MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_GCM_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_IV), MOCK_ARG (AES_GCM_KAT_VECTORS_IV_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_KAT_VECTORS_TAG_LEN));
	status |= mock_expect_output (&aes_mock.mock, 4, cipher, AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN,
		-1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_SELF_TEST_FAILED, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_gcm_kat_test_self_test_encrypt_aes256_unexpected_tag (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;
	uint8_t tag[AES_GCM_KAT_VECTORS_TAG_LEN] = {};

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY), MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_GCM_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_IV), MOCK_ARG (AES_GCM_KAT_VECTORS_IV_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_KAT_VECTORS_TAG_LEN));
	status |= mock_expect_output (&aes_mock.mock, 4, AES_GCM_KAT_VECTORS_CIPHERTEXT,
		AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN, -1);
	status |= mock_expect_output (&aes_mock.mock, 6, tag, AES_GCM_KAT_VECTORS_TAG_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_SELF_TEST_FAILED, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_gcm_kat_test_self_test_encrypt_aes256_clear_key_fail (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY), MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_GCM_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_IV), MOCK_ARG (AES_GCM_KAT_VECTORS_IV_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_GCM_KAT_VECTORS_TAG_LEN));
	status |= mock_expect_output (&aes_mock.mock, 4, AES_GCM_KAT_VECTORS_CIPHERTEXT,
		AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN, -1);
	status |= mock_expect_output (&aes_mock.mock, 6, AES_GCM_KAT_VECTORS_TAG,
		AES_GCM_KAT_VECTORS_TAG_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base,
		AES_GCM_ENGINE_INVALID_ARGUMENT);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_INVALID_ARGUMENT, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_gcm_kat_test_self_test_decrypt_aes256 (CuTest *test)
{
	int status;

	AES_GCM_TESTING_ENGINE (aes_gcm);

	TEST_START;

	status = AES_GCM_TESTING_ENGINE_INIT (&aes_gcm);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_decrypt_aes256 (&aes_gcm.base);
	CuAssertIntEquals (test, 0, status);

	AES_GCM_TESTING_ENGINE_RELEASE (&aes_gcm);
}

static void aes_gcm_kat_test_self_test_decrypt_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_gcm_kat_run_self_test_decrypt_aes256 (NULL);
	CuAssertIntEquals (test, AES_GCM_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_gcm_kat_test_self_test_decrypt_aes256_set_key_fail (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base,
		AES_GCM_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY),
		MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_SET_KEY_FAILED, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_gcm_kat_test_self_test_decrypt_aes256_decrypt_data_fail (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY), MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base,
		AES_GCM_ENGINE_DECRYPT_FAILED, MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_TAG),
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_IV), MOCK_ARG (AES_GCM_KAT_VECTORS_IV_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_DECRYPT_FAILED, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_gcm_kat_test_self_test_decrypt_aes256_unexpected_plaintext (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;
	uint8_t plaintext[AES_GCM_KAT_VECTORS_PLAINTEXT_LEN] = {};

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY), MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_TAG),
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_IV), MOCK_ARG (AES_GCM_KAT_VECTORS_IV_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 5, plaintext, AES_GCM_KAT_VECTORS_PLAINTEXT_LEN,
		-1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_SELF_TEST_FAILED, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_gcm_kat_test_self_test_decrypt_aes256_clear_key_fail (CuTest *test)
{
	int status;
	struct aes_gcm_engine_mock aes_mock;

	TEST_START;

	status = aes_gcm_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_256_KEY), MOCK_ARG (AES_GCM_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_TAG),
		MOCK_ARG_PTR (AES_GCM_KAT_VECTORS_IV), MOCK_ARG (AES_GCM_KAT_VECTORS_IV_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 5, AES_GCM_KAT_VECTORS_PLAINTEXT,
		AES_GCM_KAT_VECTORS_CIPHERTEXT_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base,
		AES_GCM_ENGINE_CLEAR_KEY_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = aes_gcm_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_GCM_ENGINE_CLEAR_KEY_FAILED, status);

	status = aes_gcm_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_ecb_kat_test_self_test_encrypt_aes256 (CuTest *test)
{
	int status;

	AES_ECB_TESTING_ENGINE (aes_ecb);

	TEST_START;

	status = AES_ECB_TESTING_ENGINE_INIT (&aes_ecb);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_encrypt_aes256 (&aes_ecb.base);
	CuAssertIntEquals (test, 0, status);

	AES_ECB_TESTING_ENGINE_RELEASE (&aes_ecb);
}

static void aes_ecb_kat_test_self_test_encrypt_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_ecb_kat_run_self_test_encrypt_aes256 (NULL);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_ecb_kat_test_self_test_encrypt_aes256_set_key_fail (CuTest *test)
{
	int status;
	struct aes_ecb_engine_mock aes_mock;

	TEST_START;

	status = aes_ecb_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base,
		AES_ECB_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_256_KEY),
		MOCK_ARG (AES_ECB_KAT_VECTORS_256_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_SET_KEY_FAILED, status);

	status = aes_ecb_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_ecb_kat_test_self_test_encrypt_aes256_ecnrypt_data_fail (CuTest *test)
{
	int status;
	struct aes_ecb_engine_mock aes_mock;

	TEST_START;

	status = aes_ecb_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_256_KEY), MOCK_ARG (AES_ECB_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base,
		AES_ECB_ENGINE_ENCRYPT_FAILED, MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_PLAINTEXT),
		MOCK_ARG (AES_ECB_KAT_VECTORS_PLAINTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN));
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_ENCRYPT_FAILED, status);

	status = aes_ecb_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_ecb_kat_test_self_test_encrypt_aes256_unexpected_cipher (CuTest *test)
{
	int status;
	struct aes_ecb_engine_mock aes_mock;
	uint8_t cipher[AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN] = {};

	TEST_START;

	status = aes_ecb_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_256_KEY), MOCK_ARG (AES_ECB_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_ECB_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 2, cipher, AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN,
		-1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_SELF_TEST_FAILED, status);

	status = aes_ecb_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_ecb_kat_test_self_test_encrypt_aes256_clear_key_fail (CuTest *test)
{
	int status;
	struct aes_ecb_engine_mock aes_mock;

	TEST_START;

	status = aes_ecb_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_256_KEY), MOCK_ARG (AES_ECB_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_ECB_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 2, AES_ECB_KAT_VECTORS_CIPHERTEXT,
		AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base,
		AES_ECB_ENGINE_CLEAR_KEY_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_CLEAR_KEY_FAILED, status);

	status = aes_ecb_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}


static void aes_ecb_kat_test_self_test_decrypt_aes256 (CuTest *test)
{
	int status;

	AES_ECB_TESTING_ENGINE (aes_ecb);

	TEST_START;

	status = AES_ECB_TESTING_ENGINE_INIT (&aes_ecb);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_decrypt_aes256 (&aes_ecb.base);
	CuAssertIntEquals (test, 0, status);

	AES_ECB_TESTING_ENGINE_RELEASE (&aes_ecb);
}

static void aes_ecb_kat_test_self_test_decrypt_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_ecb_kat_run_self_test_decrypt_aes256 (NULL);
	CuAssertIntEquals (test, AES_ECB_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_ecb_kat_test_self_test_decrypt_aes256_set_key_fail (CuTest *test)
{
	int status;
	struct aes_ecb_engine_mock aes_mock;

	TEST_START;

	status = aes_ecb_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base,
		AES_ECB_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_256_KEY),
		MOCK_ARG (AES_ECB_KAT_VECTORS_256_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_SET_KEY_FAILED, status);

	status = aes_ecb_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_ecb_kat_test_self_test_decrypt_aes256_denrypt_data_fail (CuTest *test)
{
	int status;
	struct aes_ecb_engine_mock aes_mock;

	TEST_START;

	status = aes_ecb_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_256_KEY), MOCK_ARG (AES_ECB_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base,
		AES_ECB_ENGINE_DECRYPT_FAILED, MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_ECB_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_DECRYPT_FAILED, status);

	status = aes_ecb_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_ecb_kat_test_self_test_decrypt_aes256_unexpected_plaintext (CuTest *test)
{
	int status;
	struct aes_ecb_engine_mock aes_mock;
	uint8_t plaintext[AES_ECB_KAT_VECTORS_PLAINTEXT_LEN] = {};

	TEST_START;

	status = aes_ecb_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_256_KEY), MOCK_ARG (AES_ECB_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_ECB_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 2, plaintext, AES_ECB_KAT_VECTORS_PLAINTEXT_LEN,
		-1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_SELF_TEST_FAILED, status);

	status = aes_ecb_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_ecb_kat_test_self_test_decrypt_aes256_clear_key_fail (CuTest *test)
{
	int status;
	struct aes_ecb_engine_mock aes_mock;

	TEST_START;

	status = aes_ecb_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_256_KEY), MOCK_ARG (AES_ECB_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_ECB_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_ECB_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_ECB_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 2, AES_ECB_KAT_VECTORS_PLAINTEXT,
		AES_ECB_KAT_VECTORS_PLAINTEXT_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base,
		AES_ECB_ENGINE_CLEAR_KEY_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = aes_ecb_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_ECB_ENGINE_CLEAR_KEY_FAILED, status);

	status = aes_ecb_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_cbc_kat_test_self_test_encrypt_aes256 (CuTest *test)
{
	int status;

	AES_CBC_TESTING_ENGINE (aes_cbc);

	TEST_START;

	status = AES_CBC_TESTING_ENGINE_INIT (&aes_cbc);
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_encrypt_aes256 (&aes_cbc.base);
	CuAssertIntEquals (test, 0, status);

	AES_CBC_TESTING_ENGINE_RELEASE (&aes_cbc);
}

static void aes_cbc_kat_test_self_test_encrypt_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_cbc_kat_run_self_test_encrypt_aes256 (NULL);
	CuAssertIntEquals (test, AES_CBC_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_cbc_kat_test_self_test_encrypt_aes256_set_key_fail (CuTest *test)
{
	int status;
	struct aes_cbc_engine_mock aes_mock;

	TEST_START;

	status = aes_cbc_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base,
		AES_CBC_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_256_KEY),
		MOCK_ARG (AES_CBC_KAT_VECTORS_256_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_CBC_ENGINE_SET_KEY_FAILED, status);

	status = aes_cbc_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_cbc_kat_test_self_test_encrypt_aes256_ecnrypt_data_fail (CuTest *test)
{
	int status;
	struct aes_cbc_engine_mock aes_mock;

	TEST_START;

	status = aes_cbc_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_256_KEY), MOCK_ARG (AES_CBC_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base,
		AES_CBC_ENGINE_ENCRYPT_FAILED, MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_PLAINTEXT),
		MOCK_ARG (AES_CBC_KAT_VECTORS_PLAINTEXT_LEN), MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_IV),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_ANY);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_CBC_ENGINE_ENCRYPT_FAILED, status);

	status = aes_cbc_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_cbc_kat_test_self_test_encrypt_aes256_unexpected_cipher (CuTest *test)
{
	int status;
	struct aes_cbc_engine_mock aes_mock;
	uint8_t cipher[AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN] = {};

	TEST_START;

	status = aes_cbc_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_256_KEY), MOCK_ARG (AES_CBC_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_CBC_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_IV), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_ANY);
	status |= mock_expect_output (&aes_mock.mock, 3, cipher, sizeof (cipher), -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_CBC_ENGINE_SELF_TEST_FAILED, status);

	status = aes_cbc_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_cbc_kat_test_self_test_encrypt_aes256_clear_key_fail (CuTest *test)
{
	int status;
	struct aes_cbc_engine_mock aes_mock;

	TEST_START;

	status = aes_cbc_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_256_KEY), MOCK_ARG (AES_CBC_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_CBC_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_IV), MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_ANY);
	status |= mock_expect_output (&aes_mock.mock, 3, AES_CBC_KAT_VECTORS_CIPHERTEXT,
		AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base,
		AES_CBC_ENGINE_CLEAR_KEY_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_CBC_ENGINE_CLEAR_KEY_FAILED, status);

	status = aes_cbc_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_cbc_kat_test_self_test_decrypt_aes256 (CuTest *test)
{
	int status;

	AES_CBC_TESTING_ENGINE (aes_cbc);

	TEST_START;

	status = AES_CBC_TESTING_ENGINE_INIT (&aes_cbc);
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_decrypt_aes256 (&aes_cbc.base);
	CuAssertIntEquals (test, 0, status);

	AES_CBC_TESTING_ENGINE_RELEASE (&aes_cbc);
}


static void aes_cbc_kat_test_self_test_decrypt_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_cbc_kat_run_self_test_decrypt_aes256 (NULL);
	CuAssertIntEquals (test, AES_CBC_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_cbc_kat_test_self_test_decrypt_aes256_set_key_fail (CuTest *test)
{
	int status;
	struct aes_cbc_engine_mock aes_mock;

	TEST_START;

	status = aes_cbc_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base,
		AES_CBC_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_256_KEY),
		MOCK_ARG (AES_CBC_KAT_VECTORS_256_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_CBC_ENGINE_SET_KEY_FAILED, status);

	status = aes_cbc_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_cbc_kat_test_self_test_decrypt_aes256_denrypt_data_fail (CuTest *test)
{
	int status;
	struct aes_cbc_engine_mock aes_mock;

	TEST_START;

	status = aes_cbc_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_256_KEY), MOCK_ARG (AES_CBC_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base,
		AES_CBC_ENGINE_DECRYPT_FAILED, MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_IV),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_CBC_KAT_VECTORS_PLAINTEXT_LEN), MOCK_ARG_ANY);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_CBC_ENGINE_DECRYPT_FAILED, status);

	status = aes_cbc_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_cbc_kat_test_self_test_decrypt_aes256_unexpected_plaintext (CuTest *test)
{
	int status;
	struct aes_cbc_engine_mock aes_mock;
	uint8_t plaintext[AES_CBC_KAT_VECTORS_PLAINTEXT_LEN] = {};

	TEST_START;

	status = aes_cbc_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_256_KEY), MOCK_ARG (AES_CBC_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_IV),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_CBC_KAT_VECTORS_PLAINTEXT_LEN), MOCK_ARG_ANY);
	status |= mock_expect_output (&aes_mock.mock, 3, plaintext, sizeof (plaintext), -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_CBC_ENGINE_SELF_TEST_FAILED, status);

	status = aes_cbc_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_cbc_kat_test_self_test_decrypt_aes256_clear_key_fail (CuTest *test)
{
	int status;
	struct aes_cbc_engine_mock aes_mock;

	TEST_START;

	status = aes_cbc_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_256_KEY), MOCK_ARG (AES_CBC_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_CBC_KAT_VECTORS_CIPHERTEXT_LEN), MOCK_ARG_PTR (AES_CBC_KAT_VECTORS_IV),
		MOCK_ARG_NOT_NULL, MOCK_ARG (AES_CBC_KAT_VECTORS_PLAINTEXT_LEN), MOCK_ARG_ANY);
	status |= mock_expect_output (&aes_mock.mock, 3, AES_CBC_KAT_VECTORS_PLAINTEXT,
		AES_CBC_KAT_VECTORS_PLAINTEXT_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base,
		AES_CBC_ENGINE_CLEAR_KEY_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = aes_cbc_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_CBC_ENGINE_CLEAR_KEY_FAILED, status);

	status = aes_cbc_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_xts_kat_test_self_test_encrypt_aes256 (CuTest *test)
{
	int status;

	AES_XTS_TESTING_ENGINE (aes_xts);

	TEST_START;

	status = AES_XTS_TESTING_ENGINE_INIT (&aes_xts);
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_encrypt_aes256 (&aes_xts.base);
	CuAssertIntEquals (test, 0, status);

	AES_XTS_TESTING_ENGINE_RELEASE (&aes_xts);
}

static void aes_xts_kat_test_self_test_encrypt_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_xts_kat_run_self_test_encrypt_aes256 (NULL);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_xts_kat_test_self_test_encrypt_aes256_set_key_fail (CuTest *test)
{
	int status;
	struct aes_xts_engine_mock aes_mock;

	TEST_START;

	status = aes_xts_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base,
		AES_XTS_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_256_KEY),
		MOCK_ARG (AES_XTS_KAT_VECTORS_256_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_XTS_ENGINE_SET_KEY_FAILED, status);

	status = aes_xts_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_xts_kat_test_self_test_encrypt_aes256_ecnrypt_data_fail (CuTest *test)
{
	int status;
	struct aes_xts_engine_mock aes_mock;

	TEST_START;

	status = aes_xts_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_256_KEY), MOCK_ARG (AES_XTS_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base,
		AES_XTS_ENGINE_ENCRYPT_FAILED, MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_PLAINTEXT),
		MOCK_ARG (AES_XTS_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_UNIQUE_DATA),	MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN));
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_XTS_ENGINE_ENCRYPT_FAILED, status);

	status = aes_xts_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_xts_kat_test_self_test_encrypt_aes256_unexpected_cipher (CuTest *test)
{
	int status;
	struct aes_xts_engine_mock aes_mock;
	uint8_t cipher[AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN] = {};

	TEST_START;

	status = aes_xts_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_256_KEY), MOCK_ARG (AES_XTS_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_XTS_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_UNIQUE_DATA),	MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 3, cipher, sizeof (cipher), -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_XTS_ENGINE_SELF_TEST_FAILED, status);

	status = aes_xts_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_xts_kat_test_self_test_encrypt_aes256_clear_key (CuTest *test)
{
	int status;
	struct aes_xts_engine_mock aes_mock;

	TEST_START;

	status = aes_xts_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_256_KEY), MOCK_ARG (AES_XTS_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.encrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_PLAINTEXT), MOCK_ARG (AES_XTS_KAT_VECTORS_PLAINTEXT_LEN),
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_UNIQUE_DATA),	MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 3, AES_XTS_KAT_VECTORS_CIPHERTEXT,
		AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base,
		AES_XTS_ENGINE_CLEAR_KEY_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_encrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_XTS_ENGINE_CLEAR_KEY_FAILED, status);

	status = aes_xts_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_xts_kat_test_self_test_decrypt_aes256 (CuTest *test)
{
	int status;

	AES_XTS_TESTING_ENGINE (aes_xts);

	TEST_START;

	status = AES_XTS_TESTING_ENGINE_INIT (&aes_xts);
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_decrypt_aes256 (&aes_xts.base);
	CuAssertIntEquals (test, 0, status);

	AES_XTS_TESTING_ENGINE_RELEASE (&aes_xts);
}

static void aes_xts_kat_test_self_test_decrypt_aes256_null (CuTest *test)
{
	int status;

	TEST_START;

	status = aes_xts_kat_run_self_test_decrypt_aes256 (NULL);
	CuAssertIntEquals (test, AES_XTS_ENGINE_INVALID_ARGUMENT, status);
}

static void aes_xts_kat_test_self_test_decrypt_aes256_set_key_fail (CuTest *test)
{
	int status;
	struct aes_xts_engine_mock aes_mock;

	TEST_START;

	status = aes_xts_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base,
		AES_XTS_ENGINE_SET_KEY_FAILED, MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_256_KEY),
		MOCK_ARG (AES_XTS_KAT_VECTORS_256_KEY_LEN));
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_XTS_ENGINE_SET_KEY_FAILED, status);

	status = aes_xts_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_xts_kat_test_self_test_decrypt_aes256_denrypt_data_fail (CuTest *test)
{
	int status;
	struct aes_xts_engine_mock aes_mock;

	TEST_START;

	status = aes_xts_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_256_KEY), MOCK_ARG (AES_XTS_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base,
		AES_XTS_ENGINE_DECRYPT_FAILED, MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN),
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_UNIQUE_DATA),	MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_XTS_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_XTS_ENGINE_DECRYPT_FAILED, status);

	status = aes_xts_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_xts_kat_test_self_test_decrypt_aes256_unexpected_plaintext (CuTest *test)
{
	int status;
	struct aes_xts_engine_mock aes_mock;
	uint8_t plaintext[AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN] = {};

	TEST_START;

	status = aes_xts_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_256_KEY), MOCK_ARG (AES_XTS_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN),
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_UNIQUE_DATA),	MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_XTS_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 3, plaintext, sizeof (plaintext), -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_XTS_ENGINE_SELF_TEST_FAILED, status);

	status = aes_xts_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

static void aes_xts_kat_test_self_test_decrypt_aes256_clear_key_fail (CuTest *test)
{
	int status;
	struct aes_xts_engine_mock aes_mock;

	TEST_START;

	status = aes_xts_mock_init (&aes_mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&aes_mock.mock, aes_mock.base.set_key, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_256_KEY), MOCK_ARG (AES_XTS_KAT_VECTORS_256_KEY_LEN));

	status |= mock_expect (&aes_mock.mock, aes_mock.base.decrypt_data, &aes_mock.base, 0,
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_CIPHERTEXT),
		MOCK_ARG (AES_XTS_KAT_VECTORS_CIPHERTEXT_LEN),
		MOCK_ARG_PTR (AES_XTS_KAT_VECTORS_UNIQUE_DATA),	MOCK_ARG_NOT_NULL,
		MOCK_ARG (AES_XTS_KAT_VECTORS_PLAINTEXT_LEN));
	status |= mock_expect_output (&aes_mock.mock, 3, AES_XTS_KAT_VECTORS_PLAINTEXT,
		AES_XTS_KAT_VECTORS_PLAINTEXT_LEN, -1);
	status |= mock_expect (&aes_mock.mock, aes_mock.base.clear_key, &aes_mock.base,
		AES_XTS_ENGINE_CLEAR_KEY_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = aes_xts_kat_run_self_test_decrypt_aes256 (&aes_mock.base);
	CuAssertIntEquals (test, AES_XTS_ENGINE_CLEAR_KEY_FAILED, status);

	status = aes_xts_mock_validate_and_release (&aes_mock);
	CuAssertIntEquals (test, 0, status);
}

// *INDENT-OFF*
TEST_SUITE_START (aes_kat);

TEST (aes_gcm_kat_test_self_test_encrypt_aes256);
TEST (aes_gcm_kat_test_self_test_encrypt_aes256_null);
TEST (aes_gcm_kat_test_self_test_encrypt_aes256_set_key_fail);
TEST (aes_gcm_kat_test_self_test_encrypt_aes256_encrypt_data_fail);
TEST (aes_gcm_kat_test_self_test_encrypt_aes256_unexpected_cipher);
TEST (aes_gcm_kat_test_self_test_encrypt_aes256_unexpected_tag);
TEST (aes_gcm_kat_test_self_test_encrypt_aes256_clear_key_fail);
TEST (aes_gcm_kat_test_self_test_decrypt_aes256);
TEST (aes_gcm_kat_test_self_test_decrypt_aes256_null);
TEST (aes_gcm_kat_test_self_test_decrypt_aes256_set_key_fail);
TEST (aes_gcm_kat_test_self_test_decrypt_aes256_decrypt_data_fail);
TEST (aes_gcm_kat_test_self_test_decrypt_aes256_unexpected_plaintext);
TEST (aes_gcm_kat_test_self_test_decrypt_aes256_clear_key_fail);
TEST (aes_ecb_kat_test_self_test_encrypt_aes256);
TEST (aes_ecb_kat_test_self_test_encrypt_aes256_null);
TEST (aes_ecb_kat_test_self_test_encrypt_aes256_set_key_fail);
TEST (aes_ecb_kat_test_self_test_encrypt_aes256_ecnrypt_data_fail);
TEST (aes_ecb_kat_test_self_test_encrypt_aes256_unexpected_cipher);
TEST (aes_ecb_kat_test_self_test_encrypt_aes256_clear_key_fail);
TEST (aes_ecb_kat_test_self_test_decrypt_aes256);
TEST (aes_ecb_kat_test_self_test_decrypt_aes256_null);
TEST (aes_ecb_kat_test_self_test_decrypt_aes256_set_key_fail);
TEST (aes_ecb_kat_test_self_test_decrypt_aes256_denrypt_data_fail);
TEST (aes_ecb_kat_test_self_test_decrypt_aes256_unexpected_plaintext);
TEST (aes_ecb_kat_test_self_test_decrypt_aes256_clear_key_fail);
TEST (aes_cbc_kat_test_self_test_encrypt_aes256);
TEST (aes_cbc_kat_test_self_test_encrypt_aes256_null);
TEST (aes_cbc_kat_test_self_test_encrypt_aes256_set_key_fail);
TEST (aes_cbc_kat_test_self_test_encrypt_aes256_ecnrypt_data_fail);
TEST (aes_cbc_kat_test_self_test_encrypt_aes256_unexpected_cipher);
TEST (aes_cbc_kat_test_self_test_encrypt_aes256_clear_key_fail);
TEST (aes_cbc_kat_test_self_test_decrypt_aes256);
TEST (aes_cbc_kat_test_self_test_decrypt_aes256_null);
TEST (aes_cbc_kat_test_self_test_decrypt_aes256_set_key_fail);
TEST (aes_cbc_kat_test_self_test_decrypt_aes256_denrypt_data_fail);
TEST (aes_cbc_kat_test_self_test_decrypt_aes256_unexpected_plaintext);
TEST (aes_cbc_kat_test_self_test_decrypt_aes256_clear_key_fail);
TEST (aes_xts_kat_test_self_test_encrypt_aes256);
TEST (aes_xts_kat_test_self_test_encrypt_aes256_null);
TEST (aes_xts_kat_test_self_test_encrypt_aes256_set_key_fail);
TEST (aes_xts_kat_test_self_test_encrypt_aes256_ecnrypt_data_fail);
TEST (aes_xts_kat_test_self_test_encrypt_aes256_unexpected_cipher);
TEST (aes_xts_kat_test_self_test_encrypt_aes256_clear_key);
TEST (aes_xts_kat_test_self_test_decrypt_aes256);
TEST (aes_xts_kat_test_self_test_decrypt_aes256_null);
TEST (aes_xts_kat_test_self_test_decrypt_aes256_set_key_fail);
TEST (aes_xts_kat_test_self_test_decrypt_aes256_denrypt_data_fail);
TEST (aes_xts_kat_test_self_test_decrypt_aes256_unexpected_plaintext);
TEST (aes_xts_kat_test_self_test_decrypt_aes256_clear_key_fail);

TEST_SUITE_END;
// *INDENT-ON*
