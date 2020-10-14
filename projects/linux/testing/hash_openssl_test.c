// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/hash_openssl.h"
#include "testing/hash_testing.h"


static const char *SUITE = "hash_openssl";


/*******************
 * Test cases
 *******************/

static void hash_openssl_test_init (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.calculate_sha1);
	CuAssertPtrNotNull (test, engine.base.start_sha1);
	CuAssertPtrNotNull (test, engine.base.calculate_sha256);
	CuAssertPtrNotNull (test, engine.base.start_sha256);
	CuAssertPtrNotNull (test, engine.base.calculate_sha384);
	CuAssertPtrNotNull (test, engine.base.start_sha384);
	CuAssertPtrNotNull (test, engine.base.calculate_sha512);
	CuAssertPtrNotNull (test, engine.base.start_sha512);
	CuAssertPtrNotNull (test, engine.base.update);
	CuAssertPtrNotNull (test, engine.base.finish);
	CuAssertPtrNotNull (test, engine.base.cancel);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = hash_openssl_init (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);
}

static void hash_openssl_test_release_null (CuTest *test)
{
	TEST_START;

	hash_openssl_release (NULL);
}

static void hash_openssl_test_release_no_init (CuTest *test)
{
	struct hash_engine_openssl engine;

	TEST_START;

	memset (&engine, 0, sizeof (engine));
	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha1_incremental (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha1_incremental_multi (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x7d,0xf7,0x1b,0x73,0x81,0x9f,0x2e,0x0c,0x61,0x83,0x39,0xa2,0xa4,0x53,0x08,0xa9,
		0x77,0x5e,0x3c,0x6f
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha1_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_incremental_cancel (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha1_start_incremental_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_incremental_update_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (NULL, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.update (&engine.base, NULL, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_incremental_update_no_start (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha1_update_after_finish (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_incremental_finish_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (NULL, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.finish (&engine.base, NULL, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_incremental_finish_no_start (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha1_finish_after_finish (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha1_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x7d,0xf7,0x1b,0x73,0x81,0x9f,0x2e,0x0c,0x61,0x83,0x39,0xa2,0xa4,0x53,0x08,0xa9,
		0x77,0x5e,0x3c,0x6f
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_incremental_cancel_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (NULL);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_incremental_cancel_no_start (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha256_incremental (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha256_incremental_multi (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0xa8,0xd6,0x27,0xd9,0x3f,0x51,0x8e,0x90,0x96,0xb6,0xf4,0x0e,0x36,0xd2,0x7b,0x76,
		0x60,0xfa,0x26,0xd3,0x18,0xef,0x1a,0xdc,0x43,0xda,0x75,0x0e,0x49,0xeb,0xe4,0xbe
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha256_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha256_start_incremental_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha256_update_after_finish (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha256_finish_after_finish (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha256_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0xa8,0xd6,0x27,0xd9,0x3f,0x51,0x8e,0x90,0x96,0xb6,0xf4,0x0e,0x36,0xd2,0x7b,0x76,
		0x60,0xfa,0x26,0xd3,0x18,0xef,0x1a,0xdc,0x43,0xda,0x75,0x0e,0x49,0xeb,0xe4,0xbe
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha384_incremental (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0x7b,0x8f,0x46,0x54,0x07,0x6b,0x80,0xeb,0x96,0x39,0x11,0xf1,0x9c,0xfa,0xd1,0xaa,
		0xf4,0x28,0x5e,0xd4,0x8e,0x82,0x6f,0x6c,0xde,0x1b,0x01,0xa7,0x9a,0xa7,0x3f,0xad,
		0xb5,0x44,0x6e,0x66,0x7f,0xc4,0xf9,0x04,0x17,0x78,0x2c,0x91,0x27,0x05,0x40,0xf3
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha384_incremental_multi (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0xcc,0x13,0x39,0x93,0x29,0xa2,0xcd,0x34,0x3b,0xaf,0x57,0x80,0xad,0x94,0xa2,0x2f,
		0xb8,0x26,0x02,0x51,0xf0,0x4b,0x6f,0xfa,0x8e,0x11,0x44,0x13,0x44,0x7e,0x3f,0x50,
		0x9a,0x30,0x0b,0x6b,0x82,0x9c,0x7a,0xbd,0xaf,0x98,0x29,0x8f,0x4b,0x31,0xf0,0xfc
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha384_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha384_start_incremental_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha384_update_after_finish (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0x7b,0x8f,0x46,0x54,0x07,0x6b,0x80,0xeb,0x96,0x39,0x11,0xf1,0x9c,0xfa,0xd1,0xaa,
		0xf4,0x28,0x5e,0xd4,0x8e,0x82,0x6f,0x6c,0xde,0x1b,0x01,0xa7,0x9a,0xa7,0x3f,0xad,
		0xb5,0x44,0x6e,0x66,0x7f,0xc4,0xf9,0x04,0x17,0x78,0x2c,0x91,0x27,0x05,0x40,0xf3
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha384_finish_after_finish (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0x7b,0x8f,0x46,0x54,0x07,0x6b,0x80,0xeb,0x96,0x39,0x11,0xf1,0x9c,0xfa,0xd1,0xaa,
		0xf4,0x28,0x5e,0xd4,0x8e,0x82,0x6f,0x6c,0xde,0x1b,0x01,0xa7,0x9a,0xa7,0x3f,0xad,
		0xb5,0x44,0x6e,0x66,0x7f,0xc4,0xf9,0x04,0x17,0x78,0x2c,0x91,0x27,0x05,0x40,0xf3
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha384_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0xcc,0x13,0x39,0x93,0x29,0xa2,0xcd,0x34,0x3b,0xaf,0x57,0x80,0xad,0x94,0xa2,0x2f,
		0xb8,0x26,0x02,0x51,0xf0,0x4b,0x6f,0xfa,0x8e,0x11,0x44,0x13,0x44,0x7e,0x3f,0x50,
		0x9a,0x30,0x0b,0x6b,0x82,0x9c,0x7a,0xbd,0xaf,0x98,0x29,0x8f,0x4b,0x31,0xf0,0xfc
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha512_incremental (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0xc6,0xee,0x9e,0x33,0xcf,0x5c,0x67,0x15,0xa1,0xd1,0x48,0xfd,0x73,0xf7,0x31,0x88,
		0x84,0xb4,0x1a,0xdc,0xb9,0x16,0x02,0x1e,0x2b,0xc0,0xe8,0x00,0xa5,0xc5,0xdd,0x97,
		0xf5,0x14,0x21,0x78,0xf6,0xae,0x88,0xc8,0xfd,0xd9,0x8e,0x1a,0xfb,0x0c,0xe4,0xc8,
		0xd2,0xc5,0x4b,0x5f,0x37,0xb3,0x0b,0x7d,0xa1,0x99,0x7b,0xb3,0x3b,0x0b,0x8a,0x31
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha512_incremental_multi (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0xf7,0xc8,0x74,0x28,0xfa,0xdd,0xa0,0xa5,0x5c,0x3c,0xd4,0x2f,0x35,0x3e,0xb1,0x73,
		0x4e,0xb0,0xe3,0xd1,0x8f,0x3a,0x46,0xdb,0xc5,0x35,0xf8,0xc6,0x53,0x41,0x8a,0x91,
		0x52,0xe7,0x4d,0xe7,0x40,0x27,0x04,0x98,0x35,0xf1,0x49,0x1f,0x43,0xce,0x53,0x68,
		0xbb,0xbf,0xfe,0x18,0xd8,0x53,0xbc,0xe9,0xb6,0x41,0x4c,0x52,0x0b,0x7d,0x6b,0xc6
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha512_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha512_start_incremental_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha512_update_after_finish (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0xc6,0xee,0x9e,0x33,0xcf,0x5c,0x67,0x15,0xa1,0xd1,0x48,0xfd,0x73,0xf7,0x31,0x88,
		0x84,0xb4,0x1a,0xdc,0xb9,0x16,0x02,0x1e,0x2b,0xc0,0xe8,0x00,0xa5,0xc5,0xdd,0x97,
		0xf5,0x14,0x21,0x78,0xf6,0xae,0x88,0xc8,0xfd,0xd9,0x8e,0x1a,0xfb,0x0c,0xe4,0xc8,
		0xd2,0xc5,0x4b,0x5f,0x37,0xb3,0x0b,0x7d,0xa1,0x99,0x7b,0xb3,0x3b,0x0b,0x8a,0x31
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha512_finish_after_finish (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0xc6,0xee,0x9e,0x33,0xcf,0x5c,0x67,0x15,0xa1,0xd1,0x48,0xfd,0x73,0xf7,0x31,0x88,
		0x84,0xb4,0x1a,0xdc,0xb9,0x16,0x02,0x1e,0x2b,0xc0,0xe8,0x00,0xa5,0xc5,0xdd,0x97,
		0xf5,0x14,0x21,0x78,0xf6,0xae,0x88,0xc8,0xfd,0xd9,0x8e,0x1a,0xfb,0x0c,0xe4,0xc8,
		0xd2,0xc5,0x4b,0x5f,0x37,0xb3,0x0b,0x7d,0xa1,0x99,0x7b,0xb3,0x3b,0x0b,0x8a,0x31
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_sha512_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0xf7,0xc8,0x74,0x28,0xfa,0xdd,0xa0,0xa5,0x5c,0x3c,0xd4,0x2f,0x35,0x3e,0xb1,0x73,
		0x4e,0xb0,0xe3,0xd1,0x8f,0x3a,0x46,0xdb,0xc5,0x35,0xf8,0xc6,0x53,0x41,0x8a,0x91,
		0x52,0xe7,0x4d,0xe7,0x40,0x27,0x04,0x98,0x35,0xf1,0x49,0x1f,0x43,0xce,0x53,0x68,
		0xbb,0xbf,0xfe,0x18,0xd8,0x53,0xbc,0xe9,0xb6,0x41,0x4c,0x52,0x0b,0x7d,0x6b,0xc6
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha1 (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha1_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha1_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha1 (&engine.base, NULL, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), NULL,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha1_small_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH - 1];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha256 (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha256_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha256_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha256 (&engine.base, NULL, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), NULL,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha256_small_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH - 1];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha384 (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];
	uint8_t expected[] = {
		0x7b,0x8f,0x46,0x54,0x07,0x6b,0x80,0xeb,0x96,0x39,0x11,0xf1,0x9c,0xfa,0xd1,0xaa,
		0xf4,0x28,0x5e,0xd4,0x8e,0x82,0x6f,0x6c,0xde,0x1b,0x01,0xa7,0x9a,0xa7,0x3f,0xad,
		0xb5,0x44,0x6e,0x66,0x7f,0xc4,0xf9,0x04,0x17,0x78,0x2c,0x91,0x27,0x05,0x40,0xf3
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha384_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha384_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha384 (&engine.base, NULL, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), NULL,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha384_small_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH - 1];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha512 (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];
	uint8_t expected[] = {
		0xc6,0xee,0x9e,0x33,0xcf,0x5c,0x67,0x15,0xa1,0xd1,0x48,0xfd,0x73,0xf7,0x31,0x88,
		0x84,0xb4,0x1a,0xdc,0xb9,0x16,0x02,0x1e,0x2b,0xc0,0xe8,0x00,0xa5,0xc5,0xdd,0x97,
		0xf5,0x14,0x21,0x78,0xf6,0xae,0x88,0xc8,0xfd,0xd9,0x8e,0x1a,0xfb,0x0c,0xe4,0xc8,
		0xd2,0xc5,0x4b,0x5f,0x37,0xb3,0x0b,0x7d,0xa1,0x99,0x7b,0xb3,0x3b,0x0b,0x8a,0x31
	};

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha512_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha512_null (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha512 (&engine.base, NULL, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), NULL,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_openssl_release (&engine);
}

static void hash_openssl_test_calculate_sha512_small_hash_buffer (CuTest *test)
{
	struct hash_engine_openssl engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH - 1];

	TEST_START;

	status = hash_openssl_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_openssl_release (&engine);
}


CuSuite* get_hash_openssl_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, hash_openssl_test_init);
	SUITE_ADD_TEST (suite, hash_openssl_test_init_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_release_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_release_no_init);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha1_incremental);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha1_incremental_multi);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha1_incremental_empty_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_incremental_cancel);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha1_start_incremental_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_incremental_update_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_incremental_update_no_start);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha1_update_after_finish);
	SUITE_ADD_TEST (suite, hash_openssl_test_incremental_finish_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_incremental_finish_no_start);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha1_finish_after_finish);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha1_finish_small_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_incremental_cancel_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_incremental_cancel_no_start);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha256_incremental);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha256_incremental_multi);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha256_incremental_empty_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha256_start_incremental_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha256_update_after_finish);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha256_finish_after_finish);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha256_finish_small_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha384_incremental);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha384_incremental_multi);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha384_incremental_empty_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha384_start_incremental_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha384_update_after_finish);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha384_finish_after_finish);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha384_finish_small_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha512_incremental);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha512_incremental_multi);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha512_incremental_empty_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha512_start_incremental_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha512_update_after_finish);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha512_finish_after_finish);
	SUITE_ADD_TEST (suite, hash_openssl_test_sha512_finish_small_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha1);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha1_empty_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha1_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha1_small_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha256);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha256_empty_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha256_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha256_small_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha384);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha384_empty_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha384_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha384_small_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha512);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha512_empty_hash_buffer);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha512_null);
	SUITE_ADD_TEST (suite, hash_openssl_test_calculate_sha512_small_hash_buffer);

	return suite;
}
