// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "platform_io.h"
#include "testing.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/mock/hash_mock.h"
#include "testing/hash_testing.h"


static const char *SUITE = "hash";


/**
 * SHA1 hash for testing an empty buffer.
 */
const uint8_t SHA1_EMPTY_BUFFER_HASH[] = {
	0xda,0x39,0xa3,0xee,0x5e,0x6b,0x4b,0x0d,0x32,0x55,0xbf,0xef,0x95,0x60,0x18,0x90,
	0xaf,0xd8,0x07,0x09
};

/**
 * SHA256 hash for testing an empty buffer.
 */
const uint8_t SHA256_EMPTY_BUFFER_HASH[] = {
	0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
	0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
};

/**
 * SHA256 hash for testing a 32 byte buffer filled with zeros.
 */
const uint8_t SHA256_ZERO_BUFFER_HASH[] = {
	0x66,0x68,0x7a,0xad,0xf8,0x62,0xbd,0x77,0x6c,0x8f,0xc1,0x8b,0x8e,0x9f,0x8e,0x20,
	0x08,0x97,0x14,0x85,0x6e,0xe2,0x33,0xb3,0x90,0x2a,0x59,0x1d,0x0d,0x5f,0x29,0x25
};


/*******************
 * Test cases
 *******************/

static void hash_test_hmac_sha1_incremental (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha1_incremental_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA1_BLOCK_SIZE + 1];
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x19,0x75,0xda,0x73,0x05,0xeb,0xd1,0x29,0x3a,0x90,0xc8,0x36,0xe1,0xed,0x76,0x7f,
		0xa3,0x67,0x51,0x31
	};
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256_incremental (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA256, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256_incremental_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA256_BLOCK_SIZE + 1];
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA256, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_cancel (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	hash_hmac_cancel (&hmac_engine);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_init_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (NULL, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_init (&hmac_engine, NULL, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, NULL, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, 0);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_init_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, (enum hmac_hash) 2, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_init_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_init_sha1_large_key_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	uint8_t key[SHA1_BLOCK_SIZE + 1];
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha1, &engine,
		HASH_ENGINE_SHA1_FAILED, MOCK_ARG (key), MOCK_ARG (sizeof (key)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_init_sha256_large_key_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	uint8_t key[SHA1_BLOCK_SIZE + 1];
	struct hmac_engine hmac_engine;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.calculate_sha256, &engine,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG (key), MOCK_ARG (sizeof (key)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_ANY);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA256, key, sizeof (key));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_update_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (NULL, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_update (&hmac_engine, NULL, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (NULL, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_hmac_finish (&hmac_engine, NULL, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f
	};
	struct hmac_engine hmac_engine;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_finish_inner_hash_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_HASH_LENGTH));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_finish_outer_init_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.start_sha1, &engine,
		HASH_ENGINE_START_SHA1_FAILED);
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_finish_outer_key_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_finish_outer_update_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_HASH_LENGTH));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_finish_outer_hash_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	struct hmac_engine hmac_engine;

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);
	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_HASH_LENGTH));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG (hmac), MOCK_ARG (SHA1_HASH_LENGTH));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_init (&hmac_engine, &engine.base, HMAC_SHA1, key, sizeof (key));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_update (&hmac_engine, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = hash_hmac_finish (&hmac_engine, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hmac_cancel_null (CuTest *test)
{
	TEST_START;

	hash_hmac_cancel (NULL);
}

static void hash_test_hmac_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0xfc,0x3d,0x91,0xe6,0xc1,0x13,0xd6,0x82,0x18,0x33,0xf6,0x5b,0x12,0xc7,0xe7,0x6e,
		0x7f,0x38,0x9c,0x4f
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha1_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA1_BLOCK_SIZE + 1];
	uint8_t hmac[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x19,0x75,0xda,0x73,0x05,0xeb,0xd1,0x29,0x3a,0x90,0xc8,0x36,0xe1,0xed,0x76,0x7f,
		0xa3,0x67,0x51,0x31
	};
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_sha256_large_key (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[SHA256_BLOCK_SIZE + 1];
	uint8_t hmac[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0xf1,0x3b,0x43,0x16,0x2c,0xe4,0x05,0x75,0x73,0xc5,0x54,0x10,0xad,0xd5,0xc5,0xc6,
		0x0e,0x9a,0x37,0xff,0x3e,0xa0,0x02,0x34,0xd6,0x41,0x80,0xfa,0x1a,0x0e,0x0a,0x04
	};
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (key); i++) {
		key[i] = i;
	}

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hmac, sizeof (hmac));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), (enum hmac_hash) 2, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hmac_null (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (NULL, key, sizeof (key), (uint8_t*) message, strlen (message),
		HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_generate_hmac (&engine.base, NULL, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_generate_hmac (&engine.base, key, 0, (uint8_t*) message, strlen (message),
		HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), NULL, strlen (message),
		HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, NULL, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_hash_generate_hmac_start_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine,
		HASH_ENGINE_START_SHA1_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA1_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_init_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_update_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG (message), MOCK_ARG (strlen (message)));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_finish_error (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG (message),
		MOCK_ARG (strlen (message)));

	status |= mock_expect (&engine.mock, engine.base.finish, &engine, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (SHA1_HASH_LENGTH));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_sha1_small_buffer (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA1_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha1, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA1_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA1, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_hash_generate_hmac_sha256_small_buffer (CuTest *test)
{
	struct hash_engine_mock engine;
	int status;
	char *message = "Test";
	uint8_t key[] = {0x31, 0x32, 0x33, 0x34};
	uint8_t hmac[SHA256_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.start_sha256, &engine, 0);

	status |= mock_expect (&engine.mock, engine.base.update, &engine, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_BLOCK_SIZE));
	status |= mock_expect (&engine.mock, engine.base.cancel, &engine, 0);

	CuAssertIntEquals (test, 0, status);

	status = hash_generate_hmac (&engine.base, key, sizeof (key), (uint8_t*) message,
		strlen (message), HMAC_SHA256, hmac, sizeof (hmac));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = hash_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void hash_test_start_new_hash_sha1 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_start_new_hash_sha256 (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, HASH_TYPE_SHA256);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_start_new_hash_unknown (CuTest *test)
{
	HASH_TESTING_ENGINE engine;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&engine);
	CuAssertIntEquals (test, 0, status);

	status = hash_start_new_hash (&engine.base, (enum hash_type) 10);
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	HASH_TESTING_ENGINE_RELEASE (&engine);
}

static void hash_test_start_new_hash_null (CuTest *test)
{
	int status;

	TEST_START;

	status = hash_start_new_hash (NULL, HASH_TYPE_SHA1);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);
}


CuSuite* get_hash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, hash_test_hmac_sha1_incremental);
	SUITE_ADD_TEST (suite, hash_test_hmac_sha1_incremental_large_key);
	SUITE_ADD_TEST (suite, hash_test_hmac_sha256_incremental);
	SUITE_ADD_TEST (suite, hash_test_hmac_sha256_incremental_large_key);
	SUITE_ADD_TEST (suite, hash_test_hmac_cancel);
	SUITE_ADD_TEST (suite, hash_test_hmac_init_null);
	SUITE_ADD_TEST (suite, hash_test_hmac_init_unknown);
	SUITE_ADD_TEST (suite, hash_test_hmac_init_error);
	SUITE_ADD_TEST (suite, hash_test_hmac_init_sha1_large_key_error);
	SUITE_ADD_TEST (suite, hash_test_hmac_init_sha256_large_key_error);
	SUITE_ADD_TEST (suite, hash_test_hmac_update_null);
	SUITE_ADD_TEST (suite, hash_test_hmac_finish_null);
	SUITE_ADD_TEST (suite, hash_test_hmac_finish_small_buffer);
	SUITE_ADD_TEST (suite, hash_test_hmac_finish_inner_hash_error);
	SUITE_ADD_TEST (suite, hash_test_hmac_finish_outer_init_error);
	SUITE_ADD_TEST (suite, hash_test_hmac_finish_outer_key_error);
	SUITE_ADD_TEST (suite, hash_test_hmac_finish_outer_update_error);
	SUITE_ADD_TEST (suite, hash_test_hmac_finish_outer_hash_error);
	SUITE_ADD_TEST (suite, hash_test_hmac_cancel_null);
	SUITE_ADD_TEST (suite, hash_test_hmac_sha1);
	SUITE_ADD_TEST (suite, hash_test_hmac_sha1_large_key);
	SUITE_ADD_TEST (suite, hash_test_hmac_sha256);
	SUITE_ADD_TEST (suite, hash_test_hmac_sha256_large_key);
	SUITE_ADD_TEST (suite, hash_test_hmac_unknown);
	SUITE_ADD_TEST (suite, hash_test_hmac_null);
	SUITE_ADD_TEST (suite, hash_test_hash_generate_hmac_start_error);
	SUITE_ADD_TEST (suite, hash_test_hash_generate_hmac_init_error);
	SUITE_ADD_TEST (suite, hash_test_hash_generate_hmac_update_error);
	SUITE_ADD_TEST (suite, hash_test_hash_generate_hmac_finish_error);
	SUITE_ADD_TEST (suite, hash_test_hash_generate_hmac_sha1_small_buffer);
	SUITE_ADD_TEST (suite, hash_test_hash_generate_hmac_sha256_small_buffer);
	SUITE_ADD_TEST (suite, hash_test_start_new_hash_sha1);
	SUITE_ADD_TEST (suite, hash_test_start_new_hash_sha256);
	SUITE_ADD_TEST (suite, hash_test_start_new_hash_unknown);
	SUITE_ADD_TEST (suite, hash_test_start_new_hash_null);

	return suite;
}
