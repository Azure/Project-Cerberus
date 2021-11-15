// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "riot/hash_riot.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("hash_riot");


/*******************
 * Test cases
 *******************/

static void hash_riot_test_init (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = hash_riot_init (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);
}

static void hash_riot_test_release_null (CuTest *test)
{
	TEST_START;

	hash_riot_release (NULL);
}

static void hash_riot_test_release_no_init (CuTest *test)
{
	struct hash_engine_riot engine;

	TEST_START;

	memset (&engine, 0, sizeof (engine));
	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_multi (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x7d,0xf7,0x1b,0x73,0x81,0x9f,0x2e,0x0c,0x61,0x83,0x39,0xa2,0xa4,0x53,0x08,0xa9,
		0x77,0x5e,0x3c,0x6f
	};

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_incremental_cancel (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_start_incremental_null (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_incremental_update_null (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (NULL, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.update (&engine.base, NULL, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_incremental_update_no_start (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_update_after_finish (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_incremental_finish_null (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_incremental_finish_no_start (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_finish_after_finish (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x7d,0xf7,0x1b,0x73,0x81,0x9f,0x2e,0x0c,0x61,0x83,0x39,0xa2,0xa4,0x53,0x08,0xa9,
		0x77,0x5e,0x3c,0x6f
	};

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_incremental_cancel_null (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (NULL);

	hash_riot_release (&engine);
}

static void hash_riot_test_incremental_cancel_no_start (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_multi (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0xa8,0xd6,0x27,0xd9,0x3f,0x51,0x8e,0x90,0x96,0xb6,0xf4,0x0e,0x36,0xd2,0x7b,0x76,
		0x60,0xfa,0x26,0xd3,0x18,0xef,0x1a,0xdc,0x43,0xda,0x75,0x0e,0x49,0xeb,0xe4,0xbe
	};

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_start_incremental_null (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_update_after_finish (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_finish_after_finish (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0xa8,0xd6,0x27,0xd9,0x3f,0x51,0x8e,0x90,0x96,0xb6,0xf4,0x0e,0x36,0xd2,0x7b,0x76,
		0x60,0xfa,0x26,0xd3,0x18,0xef,0x1a,0xdc,0x43,0xda,0x75,0x0e,0x49,0xeb,0xe4,0xbe
	};

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_sha384_incremental (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha512_incremental (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha1 (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];
	uint8_t expected[] = {
		0x64,0x0a,0xb2,0xba,0xe0,0x7b,0xed,0xc4,0xc1,0x63,0xf6,0x79,0xa7,0x46,0xf7,0xab,
		0x7f,0xb5,0xd1,0xfa
	};

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha1_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha1_null (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha1_small_hash_buffer (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH - 1];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha256 (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];
	uint8_t expected[] = {
		0x53,0x2e,0xaa,0xbd,0x95,0x74,0x88,0x0d,0xbf,0x76,0xb9,0xb8,0xcc,0x00,0x83,0x2c,
		0x20,0xa6,0xec,0x11,0x3d,0x68,0x22,0x99,0x55,0x0d,0x7a,0x6e,0x0f,0x34,0x5e,0x25
	};

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha256_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha256_null (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
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

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha256_small_hash_buffer (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH - 1];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha384 (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha512 (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_UNSUPPORTED_HASH, status);

	hash_riot_release (&engine);
}


TEST_SUITE_START (hash_riot);

TEST (hash_riot_test_init);
TEST (hash_riot_test_init_null);
TEST (hash_riot_test_release_null);
TEST (hash_riot_test_release_no_init);
TEST (hash_riot_test_sha1_incremental);
TEST (hash_riot_test_sha1_incremental_multi);
TEST (hash_riot_test_sha1_incremental_empty_hash_buffer);
TEST (hash_riot_test_incremental_cancel);
TEST (hash_riot_test_sha1_start_incremental_null);
TEST (hash_riot_test_incremental_update_null);
TEST (hash_riot_test_incremental_update_no_start);
TEST (hash_riot_test_sha1_update_after_finish);
TEST (hash_riot_test_incremental_finish_null);
TEST (hash_riot_test_incremental_finish_no_start);
TEST (hash_riot_test_sha1_finish_after_finish);
TEST (hash_riot_test_sha1_finish_small_hash_buffer);
TEST (hash_riot_test_incremental_cancel_null);
TEST (hash_riot_test_incremental_cancel_no_start);
TEST (hash_riot_test_sha256_incremental);
TEST (hash_riot_test_sha256_incremental_multi);
TEST (hash_riot_test_sha256_incremental_empty_hash_buffer);
TEST (hash_riot_test_sha256_start_incremental_null);
TEST (hash_riot_test_sha256_update_after_finish);
TEST (hash_riot_test_sha256_finish_after_finish);
TEST (hash_riot_test_sha256_finish_small_hash_buffer);
TEST (hash_riot_test_sha384_incremental);
TEST (hash_riot_test_sha512_incremental);
TEST (hash_riot_test_calculate_sha1);
TEST (hash_riot_test_calculate_sha1_empty_hash_buffer);
TEST (hash_riot_test_calculate_sha1_null);
TEST (hash_riot_test_calculate_sha1_small_hash_buffer);
TEST (hash_riot_test_calculate_sha256);
TEST (hash_riot_test_calculate_sha256_empty_hash_buffer);
TEST (hash_riot_test_calculate_sha256_null);
TEST (hash_riot_test_calculate_sha256_small_hash_buffer);
TEST (hash_riot_test_calculate_sha384);
TEST (hash_riot_test_calculate_sha512);

TEST_SUITE_END;
