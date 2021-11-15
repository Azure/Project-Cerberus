// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_util.h"
#include "flash/flash_common.h"
#include "crypto/ecc.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/crypto/rsa_testing.h"
#include "testing/crypto/ecc_testing.h"
#include "testing/crypto/signature_testing.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("flash_util");


/*******************
 * Test cases
 *******************/

static void flash_hash_contents_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, &hash.base, HASH_TYPE_SHA256, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_contents_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x71,0x10,0xed,0xa4,0xd0,0x9e,0x06,0x2a,0xa5,0xe4,0xa3,0x90,0xb0,0xa5,0x72,0xac,
		0x0d,0x2c,0x02,0x20
	};
	uint8_t hash_actual[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x12345),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x12345, 4, &hash.base, HASH_TYPE_SHA1, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_contents_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, &hash.base, (enum hash_type) 10,
		hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_contents_test_multiple_blocks (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_expected[] = {
		0x66,0x74,0x48,0xad,0x7b,0x51,0x35,0xd0,0xbc,0xbf,0xb4,0xbd,0x15,0x6f,0x5b,0x9b,
		0x64,0xa0,0xd8,0xab,0x68,0x71,0xa7,0xb8,0x2a,0x8c,0x68,0x0c,0x46,0xb8,0xe4,0x62
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1222),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1322),
		MOCK_ARG_NOT_NULL, MOCK_ARG (16));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_NOPE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x1122, (FLASH_VERIFICATION_BLOCK * 2) + 16,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_contents_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (NULL, 0x1122, 4, &hash.base, HASH_TYPE_SHA256, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_contents (&flash.base, 0x1122, 0, &hash.base, HASH_TYPE_SHA256, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, NULL, HASH_TYPE_SHA256, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, &hash.base, HASH_TYPE_SHA256, NULL,
		sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, &hash.base, HASH_TYPE_SHA256, hash_actual,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_contents_test_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x1122), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, &hash.base, HASH_TYPE_SHA256, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_contents_test_multiple_blocks_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_TEST, FLASH_VERIFICATION_BLOCK),
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x1222), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x1122, (FLASH_VERIFICATION_BLOCK * 2) + 16,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_contents_test_hash_start_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, &hash.base, HASH_TYPE_SHA256, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_contents_test_hash_update_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, &hash.base, HASH_TYPE_SHA256, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_contents_test_hash_finish_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (data)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG (hash_actual), MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_contents (&flash.base, 0x1122, 4, &hash.base, HASH_TYPE_SHA256, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_contents_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_contents_test_sha256_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_contents_test_sha256_no_match_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_contents_test_sha256_no_match_signature_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	memset (hash_out, 0, sizeof (hash_out));

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_contents_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base, HASH_TYPE_SHA1,
		&rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_contents_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		(enum hash_type) 10, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_UNKNOWN_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_contents_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_verify_contents (NULL, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_contents (&flash.base, 0x4321, 0, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), NULL,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, NULL, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, NULL, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, 0, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_contents_test_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_UTIL_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_contents_test_read_error_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x4321), MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));

	CuAssertIntEquals (test, 0, status);

	memcpy (hash_out, empty, sizeof (hash_out));

	status = flash_verify_contents (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_erase_region_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x10000, 256);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_multiple_blocks (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x30000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x10000, (1024 * 64 * 3));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_offset_start (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x12000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x12000, 256);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_offset_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x10000, (1024 * 64) + 15);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_multiple_blocks_offset (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x12000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x30000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x12000, (1024 * 64 * 3));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_multiple_blocks_offset_end_aligned (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x1f000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x30000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x1f000, (1024 * 64 * 2) + 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_no_length (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x10000, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_multiple_blocks_not_64k (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = 1024 * 32;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x18000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x28000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x30000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x38000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x10000, (1024 * 64 * 3));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_multiple_blocks_offset_not_64k (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = 1024 * 32;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x12000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x18000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x28000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x30000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x38000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x40000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x12000, (1024 * 64 * 3));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (NULL, 0x10000, 256);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void flash_erase_region_test_block_size_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x10000, 256);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void flash_erase_region_test_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x10000, 256);
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void flash_erase_region_test_multiple_blocks_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
		MOCK_ARG (0x20000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region (&flash.base, 0x10000, (1024 * 64 * 3));
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_data_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_program_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_data_test_offset (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x12000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x12000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_program_data (&flash.base, 0x12000, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_data_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_program_data (NULL, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_program_data (&flash.base, 0x10000, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_data_test_erase_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_program_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_data_test_write_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_program_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_data_test_incomplete_write (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x100fe));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 1,
		MOCK_ARG (0x100fe), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_program_data (&flash.base, 0x100fe, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_data_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_data_test_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t bad_data[] = {0x11, 0x22, 0x33, 0x44};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, bad_data, sizeof (bad_data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_data_test_multiple_blocks (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_data (&flash.base, 0x10000, data, (FLASH_VERIFICATION_BLOCK * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void flash_verify_data_test_multiple_blocks_mismatch_last_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t bad_data[sizeof (data)];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);

	memcpy (bad_data, data, sizeof (data));
	bad_data[(FLASH_VERIFICATION_BLOCK * 2) + 1] ^= 0x55;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, bad_data, sizeof (bad_data), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, bad_data + offset, sizeof (bad_data) - offset, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, bad_data + offset, sizeof (bad_data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_data (&flash.base, 0x10000, data, (FLASH_VERIFICATION_BLOCK * 3) - 1);
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_data_test_multiple_blocks_mismatch_middle_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t bad_data[sizeof (data)];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);

	memcpy (bad_data, data, sizeof (data));
	bad_data[(FLASH_VERIFICATION_BLOCK * 1) + 1] ^= 0x55;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, bad_data, sizeof (bad_data), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, bad_data + offset, sizeof (bad_data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_data (&flash.base, 0x10000, data, (FLASH_VERIFICATION_BLOCK * 3) - 1);
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_data_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_verify_data (NULL, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_data (&flash.base, 0x10000, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_data_test_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_and_verify_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_program_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_and_verify_test_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t check[] = {0x01, 0x02, 0x13, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, check, sizeof (check), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_program_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_program_and_verify (NULL, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_program_and_verify (&flash.base, 0x10000, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_and_verify_test_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_program_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_program_and_verify_test_verify_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_program_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_blank_check_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0xff, 0xff, 0xff, 0xff};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_blank_check (&flash.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_blank_check_test_not_blank (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0xff, 0xff, 0x11, 0xff};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_blank_check (&flash.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_blank_check_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_blank_check (NULL, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_blank_check_test_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_blank_check (&flash.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_across_erase_blocks (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x2ffff));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x30000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x2ffff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1, MOCK_ARG (0x2ffff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 1,
		MOCK_ARG (0x30000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x2ffff, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_multiple_pages (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_full_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_BLOCK_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_PAGE_SIZE,
			MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_source_higher_address (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x10000, 0x20000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_source_higher_address_full_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_BLOCK_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_PAGE_SIZE,
			MOCK_ARG (0x10000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x10000, 0x20000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_not_64k (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = 1024 * 32;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x18000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x18000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x18000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x18000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_multiple_pages_page_not_256 (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = 256 * 2;
	uint8_t data[page * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 3], data, RSA_ENCRYPT_LEN * 3);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_multiple_pages_page_offset (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20010));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 0x10),
		MOCK_ARG (page - 0x10));

	offset += page - 0x10;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0x10, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, 0x10), MOCK_ARG (0x10));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20010, 0x10000, page * 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_copy (NULL, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_no_length (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_block_check_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_not_blank (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));
	blank[sizeof (blank) - 1] = 0;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (blank)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, sizeof (blank));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_page_size_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, FLASH_PAGE_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_page_size_unsupported (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_MAX_COPY_BLOCK + 1;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (&page), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_PAGE_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_read_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_write_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_partial_write (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x2ffff));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x30000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x2ffff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1, MOCK_ARG (0x2ffff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 2,
		MOCK_ARG (0x30000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x2ffff, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_multiple_pages_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_overlapping_regions (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20000, 0x10000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_overlapping_regions_source_higher (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x10000, 0x20000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_same_erase_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x10100, 0x10000, 0x10);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_same_erase_block_at_source_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x10000, 0x20100, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_test_same_erase_block_at_destination_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy (&flash.base, 0x20100, 0x10000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_test_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t bad_data[sizeof (data)];

	TEST_START;

	memcpy (bad_data, data, sizeof (data));
	bad_data[sizeof (bad_data) - 1] ^= 0x55;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, bad_data, sizeof (bad_data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_test_multiple_pages (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy (&flash.base, 0x20000, 0x10000, (FLASH_VERIFICATION_BLOCK * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_test_multiple_pages_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t bad_data[sizeof (data)];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);

	memcpy (bad_data, data, sizeof (data));
	bad_data[(FLASH_VERIFICATION_BLOCK * 2) + 1] ^= 0x55;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, bad_data, sizeof (bad_data), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, bad_data + offset, sizeof (bad_data) - offset, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, bad_data + offset, sizeof (bad_data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy (&flash.base, 0x20000, 0x10000, (FLASH_VERIFICATION_BLOCK * 3) - 1);
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy (NULL, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_test_read_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_multiple_pages_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_full_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_BLOCK_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_PAGE_SIZE,
			MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));

		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_not_64k (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = 1024 * 32;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x18000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x18000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x18000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x18000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x18000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_multiple_pages_page_not_256 (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = 256 * 2;
	uint8_t data[page * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;
	int verify;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 3], data, RSA_ENCRYPT_LEN * 3);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;
	verify = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	offset += page;
	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	offset += page;
	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_multiple_pages_page_offset (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20010));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 0x10),
		MOCK_ARG (page - 0x10));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page - 0x10;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0x10, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, 0x10), MOCK_ARG (0x10));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20010, 0x10000, page * 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (NULL, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_block_check_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_not_blank (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));
	blank[sizeof (blank) - 1] = 0;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (blank)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, sizeof (blank));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_page_size_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, FLASH_PAGE_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_page_size_unsupported (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_MAX_COPY_BLOCK + 1;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (&page), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_PAGE_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_read_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_write_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_partial_write (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x2ffff));
	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x30000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x2ffff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1, MOCK_ARG (0x2ffff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x2ffff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 2,
		MOCK_ARG (0x30000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x2ffff, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void flash_copy_and_verify_test_overlapping_regions (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20000, 0x10000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_overlapping_regions_source_higher (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x10000, 0x20000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void flash_copy_and_verify_test_same_erase_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x10100, 0x10000, 0x10);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_same_erase_block_at_source_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x10000, 0x20100, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_and_verify_test_same_erase_block_at_destination_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_and_verify (&flash.base, 0x20100, 0x10000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_across_erase_blocks (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x2ffff));
	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x30000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x2ffff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 1, MOCK_ARG (0x2ffff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data) - 1,
		MOCK_ARG (0x30000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x2ffff, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_multiple_pages (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_full_block (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_BLOCK_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0,
			MOCK_ARG (0x20000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0,
			MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_PAGE_SIZE,
			MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_source_same_address (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x10000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_same_flash_full_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_BLOCK_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x20000));

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_PAGE_SIZE,
			MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash.base, 0x20000, &flash.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_not_64k (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = 1024 * 32;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x18000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x18000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x18000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x18000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_multiple_pages_page_not_256 (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = 256 * 2;
	uint8_t data[page * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 3], data, RSA_ENCRYPT_LEN * 3);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_multiple_pages_page_offset (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20010));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 0x10),
		MOCK_ARG (page - 0x10));

	offset += page - 0x10;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, 0x10), MOCK_ARG (0x10));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20010, &flash1.base, 0x10000, page * 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_null (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = flash_copy_ext (NULL, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_copy_ext (&flash2.base, 0x20000, NULL, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_no_length (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_block_check_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_not_blank (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));
	blank[sizeof (blank) - 1] = 0;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (blank)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (blank));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_page_size_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, FLASH_PAGE_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_page_size_unsupported (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_MAX_COPY_BLOCK + 1;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (&page), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_PAGE_SIZE, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_read_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_write_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_partial_write (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x2ffff));
	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x30000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x2ffff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 1, MOCK_ARG (0x2ffff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data) - 2,
		MOCK_ARG (0x30000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x2ffff, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_multiple_pages_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_same_flash_overlapping_regions (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash.base, 0x20000, &flash.base, 0x10000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_same_flash_overlapping_regions_source_higher (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash.base, 0x10000, &flash.base, 0x20000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_same_flash_same_erase_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash.base, 0x10100, &flash.base, 0x10000, 0x10);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_test_same_flash_same_erase_block_at_source_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash.base, 0x10000, &flash.base, 0x20100, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void flash_copy_ext_test_same_flash_same_erase_block_at_destination_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext (&flash.base, 0x20100, &flash.base, 0x10000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_ext_test (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_ext_test_mismatch (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t bad_data[sizeof (data)];

	TEST_START;

	memcpy (bad_data, data, sizeof (data));
	bad_data[sizeof (bad_data) - 1] ^= 0x55;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, bad_data, sizeof (bad_data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_ext_test_multiple_pages (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(FLASH_VERIFICATION_BLOCK * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_ext_test_multiple_pages_mismatch (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t bad_data[sizeof (data)];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);

	memcpy (bad_data, data, sizeof (data));
	bad_data[FLASH_VERIFICATION_BLOCK + 1] ^= 0x55;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash1.mock, 1, bad_data, sizeof (bad_data), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash1.mock, 1, bad_data + offset, sizeof (bad_data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(FLASH_VERIFICATION_BLOCK * 3) - 1);
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_ext_test_null (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = flash_verify_copy_ext (NULL, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_copy_ext (&flash2.base, 0x20000, NULL, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_copy_ext_test_read_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.read, &flash2, FLASH_READ_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_verify_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_same_address (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x10000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_mismatch (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_multiple_pages_mismatch (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_full_block (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_BLOCK_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0,
			MOCK_ARG (0x20000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_BLOCK_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0,
			MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_PAGE_SIZE,
			MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));

		status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0,
			MOCK_ARG (0x20000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_not_64k (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = 1024 * 32;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x18000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x18000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x18000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x18000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x18000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_multiple_pages_page_not_256 (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = 256 * 2;
	uint8_t data[page * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;
	int verify;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 3], data, RSA_ENCRYPT_LEN * 3);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;
	verify = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	offset += page;
	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	offset += page;
	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_multiple_pages_page_offset (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20010));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 0x10),
		MOCK_ARG (page - 0x10));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page - 0x10;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, 0x10), MOCK_ARG (0x10));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20010, &flash1.base, 0x10000, page * 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = flash_copy_ext_and_verify (NULL, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, NULL, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_block_check_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2,
		FLASH_BLOCK_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_not_blank (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));
	blank[sizeof (blank) - 1] = 0;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (blank)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (blank));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_page_size_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, FLASH_PAGE_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_page_size_unsupported (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_MAX_COPY_BLOCK + 1;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (&page), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_PAGE_SIZE, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_read_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_write_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_partial_write (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_block_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x2ffff));
	status |= mock_expect (&flash2.mock, flash2.base.block_erase, &flash2, 0, MOCK_ARG (0x30000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x2ffff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 1, MOCK_ARG (0x2ffff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x2ffff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data) - 2,
		MOCK_ARG (0x30000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash2.base, 0x2ffff, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_same_flash_overlapping_regions (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash.base, 0x20000, &flash.base, 0x10000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_same_flash_overlapping_source_higher (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash.base, 0x10000, &flash.base, 0x20000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_same_flash_same_erase_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash.base, 0x10100, &flash.base, 0x10000, 0x10);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_same_flash_same_erase_block_at_source_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash.base, 0x10000, &flash.base, 0x20100, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_and_verify_test_same_flash_same_erase_block_at_destination_end (
	CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_and_verify (&flash.base, 0x20100, &flash.base, 0x10000, 0x10001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_to_blank_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_to_blank (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_to_blank_and_verify_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_to_blank_and_verify (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_to_blank_test (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_to_blank (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_copy_ext_to_blank_and_verify_test (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_copy_ext_to_blank_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_and_verify_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0xff, 0xff, 0xff, 0xff};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region_and_verify (&flash.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_and_verify_test_not_blank (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;
	uint8_t data[] = {0xff, 0xff, 0xff, 0x00};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region_and_verify (&flash.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region_and_verify (NULL, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_and_verify_test_block_check_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region_and_verify (&flash.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_erase_region_and_verify_test_erase_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_BLOCK_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.block_erase, &flash, FLASH_BLOCK_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_erase_region_and_verify (&flash.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_BLOCK_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x71,0x10,0xed,0xa4,0xd0,0x9e,0x06,0x2a,0xa5,0xe4,0xa3,0x90,0xb0,0xa5,0x72,0xac,
		0x0d,0x2c,0x02,0x20
	};
	uint8_t hash_actual[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x12345),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x12345;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA1, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		(enum hash_type) 10, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_test_multiple_blocks (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_expected[] = {
		0x66,0x74,0x48,0xad,0x7b,0x51,0x35,0xd0,0xbc,0xbf,0xb4,0xbd,0x15,0x6f,0x5b,0x9b,
		0x64,0xa0,0xd8,0xab,0x68,0x71,0xa7,0xb8,0x2a,0x8c,0x68,0x0c,0x46,0xb8,0xe4,0x62
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1222),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1322),
		MOCK_ARG_NOT_NULL, MOCK_ARG (16));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_NOPE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = (FLASH_VERIFICATION_BLOCK * 2) + 16;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_test_multiple_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions[3];
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x3344),
		MOCK_ARG_NOT_NULL, MOCK_ARG (2));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x5566),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data + 3, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x1122;
	regions[0].length = 1;

	regions[1].start_addr = 0x3344;
	regions[1].length = 2;

	regions[2].start_addr = 0x5566;
	regions[2].length = 1;

	status = flash_hash_noncontiguous_contents (&flash.base, regions, 3, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents (NULL, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents (&flash.base, NULL, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 0, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, NULL,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, NULL, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_test_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x1122), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_test_multiple_blocks_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);\

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_TEST, FLASH_VERIFICATION_BLOCK),
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x1222), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = (FLASH_VERIFICATION_BLOCK * 2) + 16;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_test_multiple_regions_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions[3];
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (data, 1),
		MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x3344), MOCK_ARG_NOT_NULL, MOCK_ARG (2));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x1122;
	regions[0].length = 1;

	regions[1].start_addr = 0x3344;
	regions[1].length = 2;

	regions[2].start_addr = 0x5566;
	regions[2].length = 1;

	status = flash_hash_noncontiguous_contents (&flash.base, regions, 3, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_test_hash_start_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_test_hash_update_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_test_hash_finish_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (data)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG (hash_actual), MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_noncontiguous_contents_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_sha256_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_sha256_no_match_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_sha256_no_match_signature_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memset (hash_out, 0, sizeof (hash_out));

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA1, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		(enum hash_type) 10, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNKNOWN_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_multiple_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions[2];
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x8765),
		MOCK_ARG_NOT_NULL, MOCK_ARG (3));
	status |= mock_expect_output (&flash.mock, 1, data + 1, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x4321;
	regions[0].length = 1;

	regions[1].start_addr = 0x8765;
	regions[1].length = 3;

	status = flash_verify_noncontiguous_contents (&flash.base, regions, 2, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	struct flash_region regions;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents (NULL, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents (&flash.base, NULL, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 0, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, NULL,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, NULL, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, NULL, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, 0, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_hash_buffer_too_small (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	struct flash_region regions;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_UTIL_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_test_read_error_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memcpy (hash_out, empty, sizeof (hash_out));

	status = flash_verify_noncontiguous_contents (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_value_check_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x55, 0x55, 0x55, 0x55};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_value_check (&flash.base, 0x10000, sizeof (data), 0x55);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_value_check_test_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x55, 0x55, 0xaa, 0x55};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_value_check (&flash.base, 0x10000, sizeof (data), 0x55);
	CuAssertIntEquals (test, FLASH_UTIL_UNEXPECTED_VALUE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_value_check_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_value_check (NULL, 0x10000, 4, 0x55);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_value_check_test_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_value_check (&flash.base, 0x10000, 4, 0x55);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10000, 256);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_multiple_sectors (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10000, (1024 * 4 * 3));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_offset_start (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10200));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10200, 256);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_offset_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10000, (1024 * 4) + 15);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_multiple_sectors_offset (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10200));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x13000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10200, (1024 * 4 * 3));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_multiple_sectors_offset_end_aligned (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10f00));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10f00, (1024 * 4 * 2) + 0x100);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_no_length (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10000, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_multiple_sectors_not_4k (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10800));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11800));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12800));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10000, (1024 * 4 * 3));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_multiple_sectors_offset_not_4k (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = 1024 * 2;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10200));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10800));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11800));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12800));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x13000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10200, (1024 * 4 * 3));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (NULL, 0x10000, 256);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_sector_size_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_SECTOR_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10000, 256);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

}

static void flash_sector_erase_region_test_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_SECTOR_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10000, 256);
	CuAssertIntEquals (test, FLASH_SECTOR_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_test_multiple_sectors_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_SECTOR_ERASE_FAILED,
		MOCK_ARG (0x11000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region (&flash.base, 0x10000, (1024 * 4 * 3));
	CuAssertIntEquals (test, FLASH_SECTOR_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_and_verify_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0xff, 0xff, 0xff, 0xff};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region_and_verify (&flash.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_and_verify_test_not_blank (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0xff, 0xff, 0xff, 0x00};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region_and_verify (&flash.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region_and_verify (NULL, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_and_verify_test_sector_check_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_SECTOR_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region_and_verify (&flash.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_erase_region_and_verify_test_erase_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_SECTOR_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_erase_region_and_verify (&flash.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_SECTOR_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_data_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_data_test_offset (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10200));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10200),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_data (&flash.base, 0x10200, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_data_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_data (NULL, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_sector_program_data (&flash.base, 0x10000, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_data_test_erase_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_SECTOR_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_SECTOR_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_data_test_write_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_data (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_data_test_incomplete_write (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x100fe));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 1,
		MOCK_ARG (0x100fe), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_data (&flash.base, 0x100fe, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_and_verify_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_and_verify_test_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t check[] = {0x01, 0x02, 0x13, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, check, sizeof (check), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_and_verify (NULL, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_sector_program_and_verify (&flash.base, 0x10000, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_and_verify_test_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_SECTOR_ERASE_FAILED,
		MOCK_ARG (0x10000));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_SECTOR_ERASE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_program_and_verify_test_verify_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_program_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_across_erase_blocks (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11fff));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11fff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1, MOCK_ARG (0x11fff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 1,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x11fff, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_multiple_pages (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_full_sector (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_SECTOR_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_PAGE_SIZE,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x11000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_source_higher_address (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x10000, 0x11000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_source_higher_address_full_sector (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_SECTOR_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_PAGE_SIZE,
			MOCK_ARG (0x10000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x10000, 0x11000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_not_4k (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = 1024 * 2;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10800));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10800),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x10800, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_multiple_pages_page_not_256 (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = 256 * 2;
	uint8_t data[page * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 3], data, RSA_ENCRYPT_LEN * 3);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_multiple_pages_page_offset (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20010));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 0x10),
		MOCK_ARG (page - 0x10));

	offset += page - 0x10;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0x10, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, 0x10), MOCK_ARG (0x10));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20010, 0x10000, page * 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (NULL, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_no_length (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_sector_check_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_SECTOR_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_not_blank (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));
	blank[sizeof (blank) - 1] = 0;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (blank)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, sizeof (blank));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_page_size_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, FLASH_PAGE_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_page_size_unsupported (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_MAX_COPY_BLOCK + 1;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (&page), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_PAGE_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_read_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_write_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_partial_write (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11fff));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11fff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1, MOCK_ARG (0x11fff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 2,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x11fff, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_multiple_pages_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page),
		MOCK_ARG (page));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_overlapping_regions (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x11000, 0x10000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_overlapping_regions_source_higher (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x10000, 0x11000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_same_erase_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x10100, 0x10000, 0x10);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_same_erase_block_at_source_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x10000, 0x11100, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_test_same_erase_block_at_destination_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy (&flash.base, 0x11100, 0x10000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x20000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_multiple_pages_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_full_sector (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_SECTOR_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_PAGE_SIZE,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));

		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000 + offset),
			MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x11000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_not_4k (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = 1024 * 2;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10800));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10800),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x10800, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_multiple_pages_page_not_256 (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = 256 * 2;
	uint8_t data[page * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;
	int verify;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 3], data, RSA_ENCRYPT_LEN * 3);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;
	verify = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	offset += page;
	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	offset += page;
	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash.mock, 1, data + verify, sizeof (data) - verify, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_multiple_pages_page_offset (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20010));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page - 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 0x10),
		MOCK_ARG (page - 0x10));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page - 0x10;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, page, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0x10, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_PTR_CONTAINS (data + offset, 0x10), MOCK_ARG (0x10));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20010, 0x10000, page * 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (NULL, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_sector_check_error (CuTest *test)
{
	struct flash_mock flash;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_SECTOR_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_page_size_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, FLASH_PAGE_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_page_size_unsupported (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_MAX_COPY_BLOCK + 1;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (&page), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_PAGE_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_read_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_write_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x20000, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_partial_write (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11fff));
	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x12000));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11fff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 1, MOCK_ARG (0x11fff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11fff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 2,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x11fff, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_overlapping_regions (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x11000, 0x10000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_overlapping_regions_source_higher (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x10000, 0x11000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_same_erase_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x10100, 0x10000, 0x10);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_same_erase_block_at_source_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x10000, 0x11100, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_and_verify_test_same_erase_block_at_destination_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_and_verify (&flash.base, 0x11100, 0x10000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_across_erase_blocks (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x11fff));
	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x12000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x11fff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 1, MOCK_ARG (0x11fff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data) - 1,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x11fff, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_multiple_pages (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_full_sector (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_SECTOR_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x11000));

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0,
			MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_PAGE_SIZE,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x11000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_source_same_address (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x10000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_same_flash_full_sector (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_SECTOR_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x11000));

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash.mock, flash.base.get_page_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
			MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_PAGE_SIZE,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash.base, 0x11000, &flash.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_not_4k (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = 1024 * 2;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x10800));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x10800, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_multiple_pages_page_not_256 (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = 256 * 2;
	uint8_t data[page * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 3], data, RSA_ENCRYPT_LEN * 3);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, (page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_multiple_pages_page_offset (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20010));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 0x10),
		MOCK_ARG (page - 0x10));

	offset += page - 0x10;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, 0x10), MOCK_ARG (0x10));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20010, &flash1.base, 0x10000, page * 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_null (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = flash_sector_copy_ext (NULL, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, NULL, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_no_length (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_sector_check_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_not_blank (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));
	blank[sizeof (blank) - 1] = 0;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (blank)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (blank));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_page_size_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, FLASH_PAGE_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_page_size_unsupported (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_MAX_COPY_BLOCK + 1;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (&page), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_PAGE_SIZE, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_read_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_write_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_partial_write (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x11fff));
	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x12000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x11fff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 1, MOCK_ARG (0x11fff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data) - 2,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x11fff, &flash1.base, 0x10000, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_multiple_pages_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_same_flash_overlapping_regions (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash.base, 0x11000, &flash.base, 0x10000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_same_flash_overlapping_regions_source_higher (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash.base, 0x10000, &flash.base, 0x11000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_same_flash_same_erase_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash.base, 0x10100, &flash.base, 0x10000, 0x10);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_same_flash_same_erase_block_at_source_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash.base, 0x10000, &flash.base, 0x11100, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_test_same_flash_same_erase_block_at_destination_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext (&flash.base, 0x11100, &flash.base, 0x10000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_same_address (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x10000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_mismatch (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_multiple_pages_mismatch (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_full_sector (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[FLASH_SECTOR_SIZE];
	uint8_t blank[sizeof (data)];
	int offset;

	TEST_START;

	memset (data, 0x55, sizeof (data));
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x11000));

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_VERIFICATION_BLOCK) {
		status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
		status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);
	}

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	for (offset = 0; offset < FLASH_SECTOR_SIZE; offset += FLASH_PAGE_SIZE) {
		status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0,
			MOCK_ARG (0x10000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

		status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_PAGE_SIZE,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, FLASH_PAGE_SIZE),
			MOCK_ARG (FLASH_PAGE_SIZE));

		status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0,
			MOCK_ARG (0x11000 + offset), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_PAGE_SIZE));
		status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);
	}

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x11000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_not_4k (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = 1024 * 2;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x10800));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x10800),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x10800, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_multiple_pages_page_not_256 (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = 256 * 2;
	uint8_t data[page * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;
	int verify;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 3], data, RSA_ENCRYPT_LEN * 3);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;
	verify = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	offset += page;
	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	offset += page;
	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 1,
		MOCK_ARG (0x20000 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 1),
		MOCK_ARG (page - 1));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	verify += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000 + verify),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK - 1));
	status |= mock_expect_output (&flash2.mock, 1, data + verify, sizeof (data) - verify, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		(page * 3) - 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_multiple_pages_page_offset (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[RSA_ENCRYPT_LEN * 3];
	uint8_t blank[FLASH_VERIFICATION_BLOCK];
	int offset = 0;

	TEST_START;

	memcpy (data, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN], RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN);
	memcpy (&data[RSA_ENCRYPT_LEN * 2], RSA_ENCRYPT_BAD, RSA_ENCRYPT_LEN);
	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20010));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	offset = 0;

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page - 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page - 0x10),
		MOCK_ARG (page - 0x10));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page - 0x10));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page - 0x10;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, page,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, page), MOCK_ARG (page));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (page));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	offset += page;

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash1.mock, 1, data + offset, sizeof (data) - offset, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 0x10,
		MOCK_ARG (0x20010 + offset), MOCK_ARG_PTR_CONTAINS (data + offset, 0x10), MOCK_ARG (0x10));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20010 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (0x10));
	status |= mock_expect_output (&flash2.mock, 1, data + offset, sizeof (data) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20010, &flash1.base, 0x10000,
		page * 3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = flash_sector_copy_ext_and_verify (NULL, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, NULL, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_sector_check_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;

	TEST_START;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_not_blank (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));
	blank[sizeof (blank) - 1] = 0;

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (blank)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (blank));
	CuAssertIntEquals (test, FLASH_UTIL_NOT_BLANK, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_page_size_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, FLASH_PAGE_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_page_size_unsupported (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_MAX_COPY_BLOCK + 1;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (&page), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_PAGE_SIZE, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_read_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t blank[4];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000, 4);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_write_error (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x20000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, FLASH_WRITE_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x20000, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_partial_write (CuTest *test)
{
	struct flash_mock flash1;
	struct flash_mock flash2;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;
	uint32_t page = FLASH_PAGE_SIZE;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t blank[sizeof (data)];

	TEST_START;

	memset (blank, 0xff, sizeof (blank));

	status = flash_mock_init (&flash1);
	CuAssertIntEquals (test, 0, status);
	flash1.mock.name = "flash1";

	status = flash_mock_init (&flash2);
	CuAssertIntEquals (test, 0, status);
	flash2.mock.name = "flash2";

	status = mock_expect (&flash2.mock, flash2.base.get_sector_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x11fff));
	status |= mock_expect (&flash2.mock, flash2.base.sector_erase, &flash2, 0, MOCK_ARG (0x12000));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x11fff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash2.mock, 1, blank, sizeof (blank), 2);

	status |= mock_expect (&flash2.mock, flash2.base.get_page_size, &flash2, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash2.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash1.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, 1, MOCK_ARG (0x11fff),
		MOCK_ARG_PTR_CONTAINS (data, 1), MOCK_ARG (1));

	status |= mock_expect (&flash2.mock, flash2.base.read, &flash2, 0, MOCK_ARG (0x11fff),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash2.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash1.mock, flash1.base.read, &flash1, 0, MOCK_ARG (0x10001),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data) - 1));
	status |= mock_expect_output (&flash1.mock, 1, data + 1, sizeof (data) - 1, 2);

	status |= mock_expect (&flash2.mock, flash2.base.write, &flash2, sizeof (data) - 2,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data + 1, sizeof (data) - 1),
		MOCK_ARG (sizeof (data) - 1));

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash2.base, 0x11fff, &flash1.base, 0x10000,
		sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash1);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash2);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_same_flash_overlapping_regions (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash.base, 0x11000, &flash.base, 0x10000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_same_flash_overlapping_source_higher (
	CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash.base, 0x10000, &flash.base, 0x11000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_COPY_OVERLAP, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_same_flash_same_erase_block (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash.base, 0x10100, &flash.base, 0x10000, 0x10);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_same_flash_same_erase_block_at_source_end (
	CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash.base, 0x10000, &flash.base, 0x11100, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_sector_copy_ext_and_verify_test_same_flash_same_erase_block_at_destination_end (
	CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_sector_copy_ext_and_verify (&flash.base, 0x11100, &flash.base, 0x10000, 0x1001);
	CuAssertIntEquals (test, FLASH_UTIL_SAME_ERASE_BLOCK, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_contents_verification_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_sha256_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_sha256_no_match_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_sha256_no_match_signature_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	memset (hash_out, 0, sizeof (hash_out));

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_sha256_no_match_signature_ecc_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_NOPE, ECC_SIG_NOPE_LEN),
		MOCK_ARG (ECC_SIG_NOPE_LEN));

	CuAssertIntEquals (test, 0, status);

	memset (hash_out, 0, sizeof (hash_out));

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, ECC_SIGNATURE_NOPE, ECC_SIG_NOPE_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA1, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		(enum hash_type) 10, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNKNOWN_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_contents_verification (NULL, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_contents_verification (&flash.base, 0x4321, 0, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), NULL,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, NULL, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, NULL, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, 0, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_UTIL_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_contents_verification_test_read_error_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x4321), MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));

	CuAssertIntEquals (test, 0, status);

	memcpy (hash_out, empty, sizeof (hash_out));

	status = flash_contents_verification (&flash.base, 0x4321, strlen (data), &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_sha256_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_sha256_no_match_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_sha256_no_match_signature_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memset (hash_out, 0, sizeof (hash_out));

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_sha256_no_match_signature_ecc_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_NOPE, ECC_SIG_NOPE_LEN),
		MOCK_ARG (ECC_SIG_NOPE_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memset (hash_out, 0, sizeof (hash_out));

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, ECC_SIGNATURE_NOPE, ECC_SIG_NOPE_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA1, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		(enum hash_type) 10, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNKNOWN_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_multiple_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions[2];
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x8765),
		MOCK_ARG_NOT_NULL, MOCK_ARG (3));
	status |= mock_expect_output (&flash.mock, 1, data + 1, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x4321;
	regions[0].length = 1;

	regions[1].start_addr = 0x8765;
	regions[1].length = 3;

	status = flash_noncontiguous_contents_verification (&flash.base, regions, 2, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	struct flash_region regions;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification (NULL, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification (&flash.base, NULL, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 0, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, NULL,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, NULL, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, NULL, RSA_ENCRYPT_LEN, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, 0, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_hash_buffer_too_small (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	struct flash_region regions;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_UTIL_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_test_read_error_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x4321), MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memcpy (hash_out, empty, sizeof (hash_out));

	status = flash_noncontiguous_contents_verification (&flash.base, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, hash_out,
		sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_at_offset_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x31122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_at_offset_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x71,0x10,0xed,0xa4,0xd0,0x9e,0x06,0x2a,0xa5,0xe4,0xa3,0x90,0xb0,0xa5,0x72,0xac,
		0x0d,0x2c,0x02,0x20
	};
	uint8_t hash_actual[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x612345),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x12345;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x600000, &regions, 1,
		&hash.base, HASH_TYPE_SHA1, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_at_offset_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x10000, &regions, 1,
		&hash.base, (enum hash_type) 10, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_at_offset_test_multiple_blocks (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_expected[] = {
		0x66,0x74,0x48,0xad,0x7b,0x51,0x35,0xd0,0xbc,0xbf,0xb4,0xbd,0x15,0x6f,0x5b,0x9b,
		0x64,0xa0,0xd8,0xab,0x68,0x71,0xa7,0xb8,0x2a,0x8c,0x68,0x0c,0x46,0xb8,0xe4,0x62
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x41122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x41222),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x41322),
		MOCK_ARG_NOT_NULL, MOCK_ARG (16));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_NOPE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = (FLASH_VERIFICATION_BLOCK * 2) + 16;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x40000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_at_offset_test_multiple_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions[3];
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x71122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x73344),
		MOCK_ARG_NOT_NULL, MOCK_ARG (2));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x75566),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data + 3, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x1122;
	regions[0].length = 1;

	regions[1].start_addr = 0x3344;
	regions[1].length = 2;

	regions[2].start_addr = 0x5566;
	regions[2].length = 1;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x70000, regions, 3,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_at_offset_test_no_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_at_offset_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (NULL, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, NULL, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 0,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		NULL, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, NULL, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_noncontiguous_contents_at_offset_test_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x31122), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_at_offset_test_multiple_blocks_read_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x31122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_TEST, FLASH_VERIFICATION_BLOCK),
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x31222), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = (FLASH_VERIFICATION_BLOCK * 2) + 16;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_at_offset_test_multiple_regions_read_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions[3];
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x71122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (data, 1),
		MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x73344), MOCK_ARG_NOT_NULL, MOCK_ARG (2));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x1122;
	regions[0].length = 1;

	regions[1].start_addr = 0x3344;
	regions[1].length = 2;

	regions[2].start_addr = 0x5566;
	regions[2].length = 1;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x70000, regions, 3,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_at_offset_test_hash_start_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_at_offset_test_hash_update_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x31122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_noncontiguous_contents_at_offset_test_hash_finish_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x31122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (data)));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG (hash_actual), MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_verify_noncontiguous_contents_at_offset_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_sha256_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_sha256_no_match_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_sha256_no_match_signature_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memset (hash_out, 0, sizeof (hash_out));

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA1, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, (enum hash_type) 10, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNKNOWN_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_multiple_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions[2];
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x94321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x98765),
		MOCK_ARG_NOT_NULL, MOCK_ARG (3));
	status |= mock_expect_output (&flash.mock, 1, data + 1, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x4321;
	regions[0].length = 1;

	regions[1].start_addr = 0x8765;
	regions[1].length = 3;

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x90000, regions, 2,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_no_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0, &regions, 1, &hash.base,
		HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	struct flash_region regions;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents_at_offset (NULL, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, NULL, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 0,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		NULL, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, NULL, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, NULL, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, 0,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		NULL, NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_hash_buffer_too_small (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	struct flash_region regions;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_UTIL_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_verify_noncontiguous_contents_at_offset_test_read_error_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x54321), MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memcpy (hash_out, empty, sizeof (hash_out));

	status = flash_verify_noncontiguous_contents_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &rsa.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		&RSA_PUBLIC_KEY, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void flash_noncontiguous_contents_verification_at_offset_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_sha256_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_sha256_no_match_signature (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_sha256_no_match_signature_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		RSA_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN),
		MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memset (hash_out, 0, sizeof (hash_out));

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_NOPE, RSA_ENCRYPT_LEN,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_sha256_no_match_signature_ecc_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x54321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		ECC_ENGINE_BAD_SIGNATURE, MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN),
		MOCK_ARG (SIG_HASH_LEN), MOCK_ARG_PTR_CONTAINS (ECC_SIGNATURE_NOPE, ECC_SIG_NOPE_LEN),
		MOCK_ARG (ECC_SIG_NOPE_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memset (hash_out, 0, sizeof (hash_out));

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, ECC_SIGNATURE_NOPE, ECC_SIG_NOPE_LEN,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, ECC_ENGINE_BAD_SIGNATURE, status);

	status = testing_validate_array (SIG_HASH_TEST, hash_out, SIG_HASH_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA1, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_UNSUPPORTED_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, (enum hash_type) 10, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_UTIL_UNKNOWN_SIG_HASH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_multiple_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions[2];
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x94321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x98765),
		MOCK_ARG_NOT_NULL, MOCK_ARG (3));
	status |= mock_expect_output (&flash.mock, 1, data + 1, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x4321;
	regions[0].length = 1;

	regions[1].start_addr = 0x8765;
	regions[1].length = 3;

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x90000, regions, 2,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_no_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x4321),
		MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));
	status |= mock_expect_output (&flash.mock, 1, data, strlen (data), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification, 0,
		MOCK_ARG_PTR_CONTAINS (SIG_HASH_TEST, SIG_HASH_LEN), MOCK_ARG (SIG_HASH_LEN),
		MOCK_ARG_PTR_CONTAINS (RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN), MOCK_ARG (RSA_ENCRYPT_LEN));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	struct flash_region regions;
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification_at_offset (NULL, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, NULL, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 0,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		NULL, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, NULL, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, NULL, RSA_ENCRYPT_LEN, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, 0, NULL,
		0);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_hash_buffer_too_small (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	struct flash_region regions;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;
	char *data = "Test";

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_UTIL_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_noncontiguous_contents_verification_at_offset_test_read_error_with_hash_out (
	CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct signature_verification_mock verification;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	char *data = "Test";
	uint8_t hash_out[SHA256_HASH_LENGTH];
	uint8_t empty[sizeof (hash_out)] = {0};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x54321), MOCK_ARG_NOT_NULL, MOCK_ARG (strlen (data)));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x4321;
	regions.length = strlen (data);
	memcpy (hash_out, empty, sizeof (hash_out));

	status = flash_noncontiguous_contents_verification_at_offset (&flash.base, 0x50000, &regions, 1,
		&hash.base, HASH_TYPE_SHA256, &verification.base, RSA_SIGNATURE_TEST, RSA_ENCRYPT_LEN,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = testing_validate_array (empty, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_write_and_verify_test (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_write_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_write_and_verify_test_mismatch (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t check[] = {0x01, 0x02, 0x13, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&flash.mock, 1, check, sizeof (check), 2);

	CuAssertIntEquals (test, 0, status);

	status = flash_write_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_DATA_MISMATCH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_write_and_verify_test_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_write_and_verify (NULL, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_write_and_verify (&flash.base, 0x10000, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_write_and_verify_test_write_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_write_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_write_and_verify_test_incomplete_write (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data) - 1,
		MOCK_ARG (0x100fe), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_write_and_verify (&flash.base, 0x100fe, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_write_and_verify_test_verify_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_write_and_verify (&flash.base, 0x10000, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_contents_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_hash_update_contents (&flash.base, 0x1122, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_contents_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x71,0x10,0xed,0xa4,0xd0,0x9e,0x06,0x2a,0xa5,0xe4,0xa3,0x90,0xb0,0xa5,0x72,0xac,
		0x0d,0x2c,0x02,0x20
	};
	uint8_t hash_actual[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x12345),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha1 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_hash_update_contents (&flash.base, 0x12345, 4, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_contents_test_multiple_blocks (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_expected[] = {
		0x66,0x74,0x48,0xad,0x7b,0x51,0x35,0xd0,0xbc,0xbf,0xb4,0xbd,0x15,0x6f,0x5b,0x9b,
		0x64,0xa0,0xd8,0xab,0x68,0x71,0xa7,0xb8,0x2a,0x8c,0x68,0x0c,0x46,0xb8,0xe4,0x62
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1222),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1322),
		MOCK_ARG_NOT_NULL, MOCK_ARG (16));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_NOPE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_hash_update_contents (&flash.base, 0x1122, (FLASH_VERIFICATION_BLOCK * 2) + 16,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_contents_test_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_hash_update_contents (&flash.base, 0x1122, 0, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_contents_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_hash_update_contents (NULL, 0x1122, 4, &hash.base);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_update_contents (&flash.base, 0x1122, 4, NULL);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_contents_test_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x1122), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_update_contents (&flash.base, 0x1122, 4, &hash.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_contents_test_multiple_blocks_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_TEST, FLASH_VERIFICATION_BLOCK),
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x1222), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_update_contents (&flash.base, 0x1122, (FLASH_VERIFICATION_BLOCK * 2) + 16,
		&hash.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_contents_test_hash_update_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = flash_hash_update_contents (&flash.base, 0x1122, 4, &hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_noncontiguous_contents_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 1, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x71,0x10,0xed,0xa4,0xd0,0x9e,0x06,0x2a,0xa5,0xe4,0xa3,0x90,0xb0,0xa5,0x72,0xac,
		0x0d,0x2c,0x02,0x20
	};
	uint8_t hash_actual[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x12345),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha1 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x12345;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 1, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_test_multiple_blocks (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_expected[] = {
		0x66,0x74,0x48,0xad,0x7b,0x51,0x35,0xd0,0xbc,0xbf,0xb4,0xbd,0x15,0x6f,0x5b,0x9b,
		0x64,0xa0,0xd8,0xab,0x68,0x71,0xa7,0xb8,0x2a,0x8c,0x68,0x0c,0x46,0xb8,0xe4,0x62
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1222),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1322),
		MOCK_ARG_NOT_NULL, MOCK_ARG (16));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_NOPE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = (FLASH_VERIFICATION_BLOCK * 2) + 16;

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 1, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_test_multiple_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions[3];
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x3344),
		MOCK_ARG_NOT_NULL, MOCK_ARG (2));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x5566),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data + 3, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x1122;
	regions[0].length = 1;

	regions[1].start_addr = 0x3344;
	regions[1].length = 2;

	regions[2].start_addr = 0x5566;
	regions[2].length = 1;

	status = flash_hash_update_noncontiguous_contents (&flash.base, regions, 3, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_test_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 0;

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 1, &hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents (NULL, &regions, 1, &hash.base);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_update_noncontiguous_contents (&flash.base, NULL, 1, &hash.base);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 0, &hash.base);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 1, NULL);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_test_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x1122), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 1, &hash.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_noncontiguous_contents_test_multiple_blocks_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_TEST, FLASH_VERIFICATION_BLOCK),
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x1222), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = (FLASH_VERIFICATION_BLOCK * 2) + 16;

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 1, &hash.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_noncontiguous_contents_test_multiple_regions_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions[3];
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (data, 1),
		MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x3344), MOCK_ARG_NOT_NULL, MOCK_ARG (2));

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x1122;
	regions[0].length = 1;

	regions[1].start_addr = 0x3344;
	regions[1].length = 2;

	regions[2].start_addr = 0x5566;
	regions[2].length = 1;

	status = flash_hash_update_noncontiguous_contents (&flash.base, regions, 3, &hash.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_noncontiguous_contents_test_hash_update_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents (&flash.base, &regions, 1, &hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x31122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x71,0x10,0xed,0xa4,0xd0,0x9e,0x06,0x2a,0xa5,0xe4,0xa3,0x90,0xb0,0xa5,0x72,0xac,
		0x0d,0x2c,0x02,0x20
	};
	uint8_t hash_actual[SHA1_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x612345),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha1 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x12345;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x600000, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_multiple_blocks (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_expected[] = {
		0x66,0x74,0x48,0xad,0x7b,0x51,0x35,0xd0,0xbc,0xbf,0xb4,0xbd,0x15,0x6f,0x5b,0x9b,
		0x64,0xa0,0xd8,0xab,0x68,0x71,0xa7,0xb8,0x2a,0x8c,0x68,0x0c,0x46,0xb8,0xe4,0x62
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x41122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x41222),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST2, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x41322),
		MOCK_ARG_NOT_NULL, MOCK_ARG (16));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_NOPE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = (FLASH_VERIFICATION_BLOCK * 2) + 16;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x40000, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_multiple_regions (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions[3];
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x71122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x73344),
		MOCK_ARG_NOT_NULL, MOCK_ARG (2));
	status |= mock_expect_output (&flash.mock, 1, data + 1, sizeof (data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x75566),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data + 3, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x1122;
	regions[0].length = 1;

	regions[1].start_addr = 0x3344;
	regions[1].length = 2;

	regions[2].start_addr = 0x5566;
	regions[2].length = 1;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x70000, regions, 3,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_no_offset (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hash_expected[] = {
		0x03,0xac,0x67,0x42,0x16,0xf3,0xe1,0x5c,0x76,0x1e,0xe1,0xa5,0xe2,0x55,0xf0,0x67,
		0x95,0x36,0x23,0xc8,0xb3,0x88,0xb4,0x45,0x9e,0x13,0xf9,0x78,0xd7,0xc8,0x46,0xf4
	};
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x1122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (hash_expected, hash_actual, sizeof (hash_expected));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.start_sha256 (&hash.base);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 0;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, 0, status);

	status = hash.base.finish (&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents_at_offset (NULL, 0x30000, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x30000, NULL, 1,
		&hash.base);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 0,
		&hash.base);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		NULL);
	CuAssertIntEquals (test, FLASH_UTIL_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_read_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x31122), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_multiple_blocks_read_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x31122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, RSA_ENCRYPT_TEST, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (RSA_ENCRYPT_TEST, FLASH_VERIFICATION_BLOCK),
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x31222), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = (FLASH_VERIFICATION_BLOCK * 2) + 16;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_multiple_regions_read_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions[3];
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x71122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (1));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_PTR_CONTAINS (data, 1),
		MOCK_ARG (1));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x73344), MOCK_ARG_NOT_NULL, MOCK_ARG (2));

	CuAssertIntEquals (test, 0, status);

	regions[0].start_addr = 0x1122;
	regions[0].length = 1;

	regions[1].start_addr = 0x3344;
	regions[1].length = 2;

	regions[2].start_addr = 0x5566;
	regions[2].length = 1;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x70000, regions, 3,
		&hash.base);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}

static void flash_hash_update_noncontiguous_contents_at_offset_test_hash_update_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	int status;
	struct flash_region regions;
	uint8_t data[] = {0x31, 0x32, 0x33, 0x34};

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x31122),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	regions.start_addr = 0x1122;
	regions.length = 4;

	status = flash_hash_update_noncontiguous_contents_at_offset (&flash.base, 0x30000, &regions, 1,
		&hash.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);
}


TEST_SUITE_START  (flash_util);

TEST (flash_hash_contents_test_sha256);
TEST (flash_hash_contents_test_sha1);
TEST (flash_hash_contents_test_unknown);
TEST (flash_hash_contents_test_multiple_blocks);
TEST (flash_hash_contents_test_null);
TEST (flash_hash_contents_test_read_error);
TEST (flash_hash_contents_test_multiple_blocks_read_error);
TEST (flash_hash_contents_test_hash_start_error);
TEST (flash_hash_contents_test_hash_update_error);
TEST (flash_hash_contents_test_hash_finish_error);
TEST (flash_verify_contents_test_sha256);
TEST (flash_verify_contents_test_sha256_with_hash_out);
TEST (flash_verify_contents_test_sha256_no_match_signature);
TEST (flash_verify_contents_test_sha256_no_match_signature_with_hash_out);
TEST (flash_verify_contents_test_sha1);
TEST (flash_verify_contents_test_unknown);
TEST (flash_verify_contents_test_null);
TEST (flash_verify_contents_test_small_hash_buffer);
TEST (flash_verify_contents_test_read_error_with_hash_out);
TEST (flash_erase_region_test);
TEST (flash_erase_region_test_multiple_blocks);
TEST (flash_erase_region_test_offset_start);
TEST (flash_erase_region_test_offset_end);
TEST (flash_erase_region_test_multiple_blocks_offset);
TEST (flash_erase_region_test_multiple_blocks_offset_end_aligned);
TEST (flash_erase_region_test_no_length);
TEST (flash_erase_region_test_multiple_blocks_not_64k);
TEST (flash_erase_region_test_multiple_blocks_offset_not_64k);
TEST (flash_erase_region_test_null);
TEST (flash_erase_region_test_block_size_error);
TEST (flash_erase_region_test_error);
TEST (flash_erase_region_test_multiple_blocks_error);
TEST (flash_program_data_test);
TEST (flash_program_data_test_offset);
TEST (flash_program_data_test_null);
TEST (flash_program_data_test_erase_error);
TEST (flash_program_data_test_write_error);
TEST (flash_program_data_test_incomplete_write);
TEST (flash_verify_data_test);
TEST (flash_verify_data_test_mismatch);
TEST (flash_verify_data_test_multiple_blocks);
TEST (flash_verify_data_test_multiple_blocks_mismatch_last_block);
TEST (flash_verify_data_test_multiple_blocks_mismatch_middle_block);
TEST (flash_verify_data_test_null);
TEST (flash_verify_data_test_error);
TEST (flash_program_and_verify_test);
TEST (flash_program_and_verify_test_mismatch);
TEST (flash_program_and_verify_test_null);
TEST (flash_program_and_verify_test_error);
TEST (flash_program_and_verify_test_verify_error);
TEST (flash_blank_check_test);
TEST (flash_blank_check_test_not_blank);
TEST (flash_blank_check_test_null);
TEST (flash_blank_check_test_error);
TEST (flash_copy_test);
TEST (flash_copy_test_across_erase_blocks);
TEST (flash_copy_test_multiple_pages);
TEST (flash_copy_test_full_block);
TEST (flash_copy_test_source_higher_address);
TEST (flash_copy_test_source_higher_address_full_block);
TEST (flash_copy_test_not_64k);
TEST (flash_copy_test_multiple_pages_page_not_256);
TEST (flash_copy_test_multiple_pages_page_offset);
TEST (flash_copy_test_null);
TEST (flash_copy_test_no_length);
TEST (flash_copy_test_block_check_error);
TEST (flash_copy_test_not_blank);
TEST (flash_copy_test_page_size_error);
TEST (flash_copy_test_page_size_unsupported);
TEST (flash_copy_test_read_error);
TEST (flash_copy_test_write_error);
TEST (flash_copy_test_partial_write);
TEST (flash_copy_test_multiple_pages_error);
TEST (flash_copy_test_overlapping_regions);
TEST (flash_copy_test_overlapping_regions_source_higher);
TEST (flash_copy_test_same_erase_block);
TEST (flash_copy_test_same_erase_block_at_source_end);
TEST (flash_copy_test_same_erase_block_at_destination_end);
TEST (flash_verify_copy_test);
TEST (flash_verify_copy_test_mismatch);
TEST (flash_verify_copy_test_multiple_pages);
TEST (flash_verify_copy_test_multiple_pages_mismatch);
TEST (flash_verify_copy_test_null);
TEST (flash_verify_copy_test_read_error);
TEST (flash_copy_and_verify_test);
TEST (flash_copy_and_verify_test_mismatch);
TEST (flash_copy_and_verify_test_multiple_pages_mismatch);
TEST (flash_copy_and_verify_test_full_block);
TEST (flash_copy_and_verify_test_not_64k);
TEST (flash_copy_and_verify_test_multiple_pages_page_not_256);
TEST (flash_copy_and_verify_test_multiple_pages_page_offset);
TEST (flash_copy_and_verify_test_null);
TEST (flash_copy_and_verify_test_block_check_error);
TEST (flash_copy_and_verify_test_not_blank);
TEST (flash_copy_and_verify_test_page_size_error);
TEST (flash_copy_and_verify_test_page_size_unsupported);
TEST (flash_copy_and_verify_test_read_error);
TEST (flash_copy_and_verify_test_write_error);
TEST (flash_copy_and_verify_test_partial_write);
TEST (flash_copy_and_verify_test_overlapping_regions);
TEST (flash_copy_and_verify_test_overlapping_regions_source_higher);
TEST (flash_copy_and_verify_test_same_erase_block);
TEST (flash_copy_and_verify_test_same_erase_block_at_source_end);
TEST (flash_copy_and_verify_test_same_erase_block_at_destination_end);
TEST (flash_copy_ext_test);
TEST (flash_copy_ext_test_across_erase_blocks);
TEST (flash_copy_ext_test_multiple_pages);
TEST (flash_copy_ext_test_full_block);
TEST (flash_copy_ext_test_source_same_address);
TEST (flash_copy_ext_test_same_flash_full_block);
TEST (flash_copy_ext_test_not_64k);
TEST (flash_copy_ext_test_multiple_pages_page_not_256);
TEST (flash_copy_ext_test_multiple_pages_page_offset);
TEST (flash_copy_ext_test_null);
TEST (flash_copy_ext_test_no_length);
TEST (flash_copy_ext_test_block_check_error);
TEST (flash_copy_ext_test_not_blank);
TEST (flash_copy_ext_test_page_size_error);
TEST (flash_copy_ext_test_page_size_unsupported);
TEST (flash_copy_ext_test_read_error);
TEST (flash_copy_ext_test_write_error);
TEST (flash_copy_ext_test_partial_write);
TEST (flash_copy_ext_test_multiple_pages_error);
TEST (flash_copy_ext_test_same_flash_overlapping_regions);
TEST (flash_copy_ext_test_same_flash_overlapping_regions_source_higher);
TEST (flash_copy_ext_test_same_flash_same_erase_block);
TEST (flash_copy_ext_test_same_flash_same_erase_block_at_source_end);
TEST (flash_copy_ext_test_same_flash_same_erase_block_at_destination_end);
TEST (flash_verify_copy_ext_test);
TEST (flash_verify_copy_ext_test_mismatch);
TEST (flash_verify_copy_ext_test_multiple_pages);
TEST (flash_verify_copy_ext_test_multiple_pages_mismatch);
TEST (flash_verify_copy_ext_test_null);
TEST (flash_verify_copy_ext_test_read_error);
TEST (flash_copy_ext_and_verify_test);
TEST (flash_copy_ext_and_verify_test_same_address);
TEST (flash_copy_ext_and_verify_test_mismatch);
TEST (flash_copy_ext_and_verify_test_multiple_pages_mismatch);
TEST (flash_copy_ext_and_verify_test_full_block);
TEST (flash_copy_ext_and_verify_test_not_64k);
TEST (flash_copy_ext_and_verify_test_multiple_pages_page_not_256);
TEST (flash_copy_ext_and_verify_test_multiple_pages_page_offset);
TEST (flash_copy_ext_and_verify_test_null);
TEST (flash_copy_ext_and_verify_test_block_check_error);
TEST (flash_copy_ext_and_verify_test_not_blank);
TEST (flash_copy_ext_and_verify_test_page_size_error);
TEST (flash_copy_ext_and_verify_test_page_size_unsupported);
TEST (flash_copy_ext_and_verify_test_read_error);
TEST (flash_copy_ext_and_verify_test_write_error);
TEST (flash_copy_ext_and_verify_test_partial_write);
TEST (flash_copy_ext_and_verify_test_same_flash_overlapping_regions);
TEST (flash_copy_ext_and_verify_test_same_flash_overlapping_source_higher);
TEST (flash_copy_ext_and_verify_test_same_flash_same_erase_block);
TEST (flash_copy_ext_and_verify_test_same_flash_same_erase_block_at_source_end);
TEST (flash_copy_ext_and_verify_test_same_flash_same_erase_block_at_destination_end);
TEST (flash_copy_to_blank_test);
TEST (flash_copy_to_blank_and_verify_test);
TEST (flash_copy_ext_to_blank_test);
TEST (flash_copy_ext_to_blank_and_verify_test);
TEST (flash_erase_region_and_verify_test);
TEST (flash_erase_region_and_verify_test_not_blank);
TEST (flash_erase_region_and_verify_test_null);
TEST (flash_erase_region_and_verify_test_block_check_error);
TEST (flash_erase_region_and_verify_test_erase_error);
TEST (flash_hash_noncontiguous_contents_test_sha256);
TEST (flash_hash_noncontiguous_contents_test_sha1);
TEST (flash_hash_noncontiguous_contents_test_unknown);
TEST (flash_hash_noncontiguous_contents_test_multiple_blocks);
TEST (flash_hash_noncontiguous_contents_test_multiple_regions);
TEST (flash_hash_noncontiguous_contents_test_null);
TEST (flash_hash_noncontiguous_contents_test_read_error);
TEST (flash_hash_noncontiguous_contents_test_multiple_blocks_read_error);
TEST (flash_hash_noncontiguous_contents_test_multiple_regions_read_error);
TEST (flash_hash_noncontiguous_contents_test_hash_start_error);
TEST (flash_hash_noncontiguous_contents_test_hash_update_error);
TEST (flash_hash_noncontiguous_contents_test_hash_finish_error);
TEST (flash_verify_noncontiguous_contents_test_sha256);
TEST (flash_verify_noncontiguous_contents_test_sha256_with_hash_out);
TEST (flash_verify_noncontiguous_contents_test_sha256_no_match_signature);
TEST (flash_verify_noncontiguous_contents_test_sha256_no_match_signature_with_hash_out);
TEST (flash_verify_noncontiguous_contents_test_sha1);
TEST (flash_verify_noncontiguous_contents_test_unknown);
TEST (flash_verify_noncontiguous_contents_test_multiple_regions);
TEST (flash_verify_noncontiguous_contents_test_null);
TEST (flash_verify_noncontiguous_contents_test_hash_buffer_too_small);
TEST (flash_verify_noncontiguous_contents_test_read_error_with_hash_out);
TEST (flash_value_check_test);
TEST (flash_value_check_test_mismatch);
TEST (flash_value_check_test_null);
TEST (flash_value_check_test_error);
TEST (flash_sector_erase_region_test);
TEST (flash_sector_erase_region_test_multiple_sectors);
TEST (flash_sector_erase_region_test_offset_start);
TEST (flash_sector_erase_region_test_offset_end);
TEST (flash_sector_erase_region_test_multiple_sectors_offset);
TEST (flash_sector_erase_region_test_multiple_sectors_offset_end_aligned);
TEST (flash_sector_erase_region_test_no_length);
TEST (flash_sector_erase_region_test_multiple_sectors_not_4k);
TEST (flash_sector_erase_region_test_multiple_sectors_offset_not_4k);
TEST (flash_sector_erase_region_test_null);
TEST (flash_sector_erase_region_test_sector_size_error);
TEST (flash_sector_erase_region_test_error);
TEST (flash_sector_erase_region_test_multiple_sectors_error);
TEST (flash_sector_erase_region_and_verify_test);
TEST (flash_sector_erase_region_and_verify_test_not_blank);
TEST (flash_sector_erase_region_and_verify_test_null);
TEST (flash_sector_erase_region_and_verify_test_sector_check_error);
TEST (flash_sector_erase_region_and_verify_test_erase_error);
TEST (flash_sector_program_data_test);
TEST (flash_sector_program_data_test_offset);
TEST (flash_sector_program_data_test_null);
TEST (flash_sector_program_data_test_erase_error);
TEST (flash_sector_program_data_test_write_error);
TEST (flash_sector_program_data_test_incomplete_write);
TEST (flash_sector_program_and_verify_test);
TEST (flash_sector_program_and_verify_test_mismatch);
TEST (flash_sector_program_and_verify_test_null);
TEST (flash_sector_program_and_verify_test_error);
TEST (flash_sector_program_and_verify_test_verify_error);
TEST (flash_sector_copy_test);
TEST (flash_sector_copy_test_across_erase_blocks);
TEST (flash_sector_copy_test_multiple_pages);
TEST (flash_sector_copy_test_full_sector);
TEST (flash_sector_copy_test_source_higher_address);
TEST (flash_sector_copy_test_source_higher_address_full_sector);
TEST (flash_sector_copy_test_not_4k);
TEST (flash_sector_copy_test_multiple_pages_page_not_256);
TEST (flash_sector_copy_test_multiple_pages_page_offset);
TEST (flash_sector_copy_test_null);
TEST (flash_sector_copy_test_no_length);
TEST (flash_sector_copy_test_sector_check_error);
TEST (flash_sector_copy_test_not_blank);
TEST (flash_sector_copy_test_page_size_error);
TEST (flash_sector_copy_test_page_size_unsupported);
TEST (flash_sector_copy_test_read_error);
TEST (flash_sector_copy_test_write_error);
TEST (flash_sector_copy_test_partial_write);
TEST (flash_sector_copy_test_multiple_pages_error);
TEST (flash_sector_copy_test_overlapping_regions);
TEST (flash_sector_copy_test_overlapping_regions_source_higher);
TEST (flash_sector_copy_test_same_erase_block);
TEST (flash_sector_copy_test_same_erase_block_at_source_end);
TEST (flash_sector_copy_test_same_erase_block_at_destination_end);
TEST (flash_sector_copy_and_verify_test);
TEST (flash_sector_copy_and_verify_test_mismatch);
TEST (flash_sector_copy_and_verify_test_multiple_pages_mismatch);
TEST (flash_sector_copy_and_verify_test_full_sector);
TEST (flash_sector_copy_and_verify_test_not_4k);
TEST (flash_sector_copy_and_verify_test_multiple_pages_page_not_256);
TEST (flash_sector_copy_and_verify_test_multiple_pages_page_offset);
TEST (flash_sector_copy_and_verify_test_null);
TEST (flash_sector_copy_and_verify_test_sector_check_error);
TEST (flash_sector_copy_and_verify_test_page_size_error);
TEST (flash_sector_copy_and_verify_test_page_size_unsupported);
TEST (flash_sector_copy_and_verify_test_read_error);
TEST (flash_sector_copy_and_verify_test_write_error);
TEST (flash_sector_copy_and_verify_test_partial_write);
TEST (flash_sector_copy_and_verify_test_overlapping_regions);
TEST (flash_sector_copy_and_verify_test_overlapping_regions_source_higher);
TEST (flash_sector_copy_and_verify_test_same_erase_block);
TEST (flash_sector_copy_and_verify_test_same_erase_block_at_source_end);
TEST (flash_sector_copy_and_verify_test_same_erase_block_at_destination_end);
TEST (flash_sector_copy_ext_test);
TEST (flash_sector_copy_ext_test_across_erase_blocks);
TEST (flash_sector_copy_ext_test_multiple_pages);
TEST (flash_sector_copy_ext_test_full_sector);
TEST (flash_sector_copy_ext_test_source_same_address);
TEST (flash_sector_copy_ext_test_same_flash_full_sector);
TEST (flash_sector_copy_ext_test_not_4k);
TEST (flash_sector_copy_ext_test_multiple_pages_page_not_256);
TEST (flash_sector_copy_ext_test_multiple_pages_page_offset);
TEST (flash_sector_copy_ext_test_null);
TEST (flash_sector_copy_ext_test_no_length);
TEST (flash_sector_copy_ext_test_sector_check_error);
TEST (flash_sector_copy_ext_test_not_blank);
TEST (flash_sector_copy_ext_test_page_size_error);
TEST (flash_sector_copy_ext_test_page_size_unsupported);
TEST (flash_sector_copy_ext_test_read_error);
TEST (flash_sector_copy_ext_test_write_error);
TEST (flash_sector_copy_ext_test_partial_write);
TEST (flash_sector_copy_ext_test_multiple_pages_error);
TEST (flash_sector_copy_ext_test_same_flash_overlapping_regions);
TEST (flash_sector_copy_ext_test_same_flash_overlapping_regions_source_higher);
TEST (flash_sector_copy_ext_test_same_flash_same_erase_block);
TEST (flash_sector_copy_ext_test_same_flash_same_erase_block_at_source_end);
TEST (flash_sector_copy_ext_test_same_flash_same_erase_block_at_destination_end);
TEST (flash_sector_copy_ext_and_verify_test);
TEST (flash_sector_copy_ext_and_verify_test_same_address);
TEST (flash_sector_copy_ext_and_verify_test_mismatch);
TEST (flash_sector_copy_ext_and_verify_test_multiple_pages_mismatch);
TEST (flash_sector_copy_ext_and_verify_test_full_sector);
TEST (flash_sector_copy_ext_and_verify_test_not_4k);
TEST (flash_sector_copy_ext_and_verify_test_multiple_pages_page_not_256);
TEST (flash_sector_copy_ext_and_verify_test_multiple_pages_page_offset);
TEST (flash_sector_copy_ext_and_verify_test_null);
TEST (flash_sector_copy_ext_and_verify_test_sector_check_error);
TEST (flash_sector_copy_ext_and_verify_test_not_blank);
TEST (flash_sector_copy_ext_and_verify_test_page_size_error);
TEST (flash_sector_copy_ext_and_verify_test_page_size_unsupported);
TEST (flash_sector_copy_ext_and_verify_test_read_error);
TEST (flash_sector_copy_ext_and_verify_test_write_error);
TEST (flash_sector_copy_ext_and_verify_test_partial_write);
TEST (flash_sector_copy_ext_and_verify_test_same_flash_overlapping_regions);
TEST (flash_sector_copy_ext_and_verify_test_same_flash_overlapping_source_higher);
TEST (flash_sector_copy_ext_and_verify_test_same_flash_same_erase_block);
TEST (flash_sector_copy_ext_and_verify_test_same_flash_same_erase_block_at_source_end);
TEST (flash_sector_copy_ext_and_verify_test_same_flash_same_erase_block_at_destination_end);
TEST (flash_contents_verification_test_sha256);
TEST (flash_contents_verification_test_sha256_with_hash_out);
TEST (flash_contents_verification_test_sha256_no_match_signature);
TEST (flash_contents_verification_test_sha256_no_match_signature_with_hash_out);
TEST (flash_contents_verification_test_sha256_no_match_signature_ecc_with_hash_out);
TEST (flash_contents_verification_test_sha1);
TEST (flash_contents_verification_test_unknown);
TEST (flash_contents_verification_test_null);
TEST (flash_contents_verification_test_small_hash_buffer);
TEST (flash_contents_verification_test_read_error_with_hash_out);
TEST (flash_noncontiguous_contents_verification_test_sha256);
TEST (flash_noncontiguous_contents_verification_test_sha256_with_hash_out);
TEST (flash_noncontiguous_contents_verification_test_sha256_no_match_signature);
TEST (flash_noncontiguous_contents_verification_test_sha256_no_match_signature_with_hash_out);
TEST (flash_noncontiguous_contents_verification_test_sha256_no_match_signature_ecc_with_hash_out);
TEST (flash_noncontiguous_contents_verification_test_sha1);
TEST (flash_noncontiguous_contents_verification_test_unknown);
TEST (flash_noncontiguous_contents_verification_test_multiple_regions);
TEST (flash_noncontiguous_contents_verification_test_null);
TEST (flash_noncontiguous_contents_verification_test_hash_buffer_too_small);
TEST (flash_noncontiguous_contents_verification_test_read_error_with_hash_out);
TEST (flash_hash_noncontiguous_contents_at_offset_test_sha256);
TEST (flash_hash_noncontiguous_contents_at_offset_test_sha1);
TEST (flash_hash_noncontiguous_contents_at_offset_test_unknown);
TEST (flash_hash_noncontiguous_contents_at_offset_test_multiple_blocks);
TEST (flash_hash_noncontiguous_contents_at_offset_test_multiple_regions);
TEST (flash_hash_noncontiguous_contents_at_offset_test_no_offset);
TEST (flash_hash_noncontiguous_contents_at_offset_test_null);
TEST (flash_hash_noncontiguous_contents_at_offset_test_read_error);
TEST (flash_hash_noncontiguous_contents_at_offset_test_multiple_blocks_read_error);
TEST (flash_hash_noncontiguous_contents_at_offset_test_multiple_regions_read_error);
TEST (flash_hash_noncontiguous_contents_at_offset_test_hash_start_error);
TEST (flash_hash_noncontiguous_contents_at_offset_test_hash_update_error);
TEST (flash_hash_noncontiguous_contents_at_offset_test_hash_finish_error);
TEST (flash_verify_noncontiguous_contents_at_offset_test_sha256);
TEST (flash_verify_noncontiguous_contents_at_offset_test_sha256_with_hash_out);
TEST (flash_verify_noncontiguous_contents_at_offset_test_sha256_no_match_signature);
TEST (flash_verify_noncontiguous_contents_at_offset_test_sha256_no_match_signature_with_hash_out);
TEST (flash_verify_noncontiguous_contents_at_offset_test_sha1);
TEST (flash_verify_noncontiguous_contents_at_offset_test_unknown);
TEST (flash_verify_noncontiguous_contents_at_offset_test_multiple_regions);
TEST (flash_verify_noncontiguous_contents_at_offset_test_no_offset);
TEST (flash_verify_noncontiguous_contents_at_offset_test_null);
TEST (flash_verify_noncontiguous_contents_at_offset_test_hash_buffer_too_small);
TEST (flash_verify_noncontiguous_contents_at_offset_test_read_error_with_hash_out);
TEST (flash_noncontiguous_contents_verification_at_offset_test_sha256);
TEST (flash_noncontiguous_contents_verification_at_offset_test_sha256_with_hash_out);
TEST (flash_noncontiguous_contents_verification_at_offset_test_sha256_no_match_signature);
TEST (flash_noncontiguous_contents_verification_at_offset_test_sha256_no_match_signature_with_hash_out);
TEST (flash_noncontiguous_contents_verification_at_offset_test_sha256_no_match_signature_ecc_with_hash_out);
TEST (flash_noncontiguous_contents_verification_at_offset_test_sha1);
TEST (flash_noncontiguous_contents_verification_at_offset_test_unknown);
TEST (flash_noncontiguous_contents_verification_at_offset_test_multiple_regions);
TEST (flash_noncontiguous_contents_verification_at_offset_test_no_offset);
TEST (flash_noncontiguous_contents_verification_at_offset_test_null);
TEST (flash_noncontiguous_contents_verification_at_offset_test_hash_buffer_too_small);
TEST (flash_noncontiguous_contents_verification_at_offset_test_read_error_with_hash_out);
TEST (flash_write_and_verify_test);
TEST (flash_write_and_verify_test_mismatch);
TEST (flash_write_and_verify_test_null);
TEST (flash_write_and_verify_test_write_error);
TEST (flash_write_and_verify_test_incomplete_write);
TEST (flash_write_and_verify_test_verify_error);
TEST (flash_hash_update_contents_test_sha256);
TEST (flash_hash_update_contents_test_sha1);
TEST (flash_hash_update_contents_test_multiple_blocks);
TEST (flash_hash_update_contents_test_zero_length);
TEST (flash_hash_update_contents_test_null);
TEST (flash_hash_update_contents_test_read_error);
TEST (flash_hash_update_contents_test_multiple_blocks_read_error);
TEST (flash_hash_update_contents_test_hash_update_error);
TEST (flash_hash_update_noncontiguous_contents_test_sha256);
TEST (flash_hash_update_noncontiguous_contents_test_sha1);
TEST (flash_hash_update_noncontiguous_contents_test_multiple_blocks);
TEST (flash_hash_update_noncontiguous_contents_test_multiple_regions);
TEST (flash_hash_update_noncontiguous_contents_test_zero_length);
TEST (flash_hash_update_noncontiguous_contents_test_null);
TEST (flash_hash_update_noncontiguous_contents_test_read_error);
TEST (flash_hash_update_noncontiguous_contents_test_multiple_blocks_read_error);
TEST (flash_hash_update_noncontiguous_contents_test_multiple_regions_read_error);
TEST (flash_hash_update_noncontiguous_contents_test_hash_update_error);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_sha256);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_sha1);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_multiple_blocks);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_multiple_regions);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_no_offset);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_zero_length);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_null);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_read_error);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_multiple_blocks_read_error);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_multiple_regions_read_error);
TEST (flash_hash_update_noncontiguous_contents_at_offset_test_hash_update_error);

TEST_SUITE_END;
