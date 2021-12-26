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

#ifdef HASH_ENABLE_SHA1
	CuAssertPtrNotNull (test, engine.base.calculate_sha1);
	CuAssertPtrNotNull (test, engine.base.start_sha1);
#endif
	CuAssertPtrNotNull (test, engine.base.calculate_sha256);
	CuAssertPtrNotNull (test, engine.base.start_sha256);
#ifdef HASH_ENABLE_SHA384
	CuAssertPtrNotNull (test, engine.base.calculate_sha384);
	CuAssertPtrNotNull (test, engine.base.start_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
	CuAssertPtrNotNull (test, engine.base.calculate_sha512);
	CuAssertPtrNotNull (test, engine.base.start_sha512);
#endif
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

#ifdef HASH_ENABLE_SHA1
static void hash_riot_test_sha1_incremental (CuTest *test)
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

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_multi (CuTest *test)
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

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_full_hash_block (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_512[i * (HASH_TESTING_FULL_BLOCK_512_LEN / 4)],
			HASH_TESTING_FULL_BLOCK_512_LEN / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_multiple_hash_blocks_single_update (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_2048_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_multiple_hash_blocks_partial_update (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_FULL_BLOCK_2048[8],
		HASH_TESTING_FULL_BLOCK_2048_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[8],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_partial_block_480_bits (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_480,
		HASH_TESTING_PARTIAL_BLOCK_480_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_480_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_partial_block_448_bits (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_448,
		HASH_TESTING_PARTIAL_BLOCK_448_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_448_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_partial_block_440_bits (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_440,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_440_HASH, hash, sizeof (hash));
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

static void hash_riot_test_sha1_incremental_after_finish (CuTest *test)
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

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_incremental_cancel (CuTest *test)
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

static void hash_riot_test_sha1_incremental_after_cancel (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);

	engine.base.cancel (&engine.base);

	/* Run a new hash to see that it is calculated correctly. */
	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[8],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

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

static void hash_riot_test_sha1_start_without_finish (CuTest *test)
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

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_IN_PROGRESS, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_update_after_finish (CuTest *test)
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

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha1_finish_after_finish (CuTest *test)
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

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
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

	status = testing_validate_array (SHA1_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}
#endif

static void hash_riot_test_sha256_incremental (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_multi (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

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

	status = testing_validate_array (SHA256_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_full_hash_block (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_512[i * (HASH_TESTING_FULL_BLOCK_512_LEN / 4)],
			HASH_TESTING_FULL_BLOCK_512_LEN / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_multiple_hash_blocks_single_update (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_2048_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_multiple_hash_blocks_partial_update (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_FULL_BLOCK_2048[8],
		HASH_TESTING_FULL_BLOCK_2048_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[8],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_partial_block_480_bits (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_480,
		HASH_TESTING_PARTIAL_BLOCK_480_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_480_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_partial_block_448_bits (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_448,
		HASH_TESTING_PARTIAL_BLOCK_448_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_448_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_partial_block_440_bits (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_440,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_440_HASH, hash, sizeof (hash));
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

static void hash_riot_test_sha256_incremental_after_finish (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_cancel (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_incremental_after_cancel (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);

	engine.base.cancel (&engine.base);

	/* Run a new hash to see that it is calculated correctly. */
	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[8],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
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

static void hash_riot_test_sha256_start_without_finish (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_IN_PROGRESS, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_sha256_update_after_finish (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
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

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
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

	status = testing_validate_array (SHA256_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

#ifdef HASH_ENABLE_SHA384
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
#endif

#ifdef HASH_ENABLE_SHA512
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
#endif

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

#ifdef HASH_ENABLE_SHA1
static void hash_riot_test_calculate_sha1 (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha1_full_hash_block (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha1_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
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

static void hash_riot_test_calculate_sha1_without_finish (CuTest *test)
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

	status = engine.base.calculate_sha1 (&engine.base, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_2048_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_IN_PROGRESS, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

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
#endif

static void hash_riot_test_calculate_sha256 (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha256_full_hash_block (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_riot_release (&engine);
}

static void hash_riot_test_calculate_sha256_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
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

static void hash_riot_test_calculate_sha256_without_finish (CuTest *test)
{
	struct hash_engine_riot engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));

	status = engine.base.calculate_sha256 (&engine.base, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_2048_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_IN_PROGRESS, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

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

#ifdef HASH_ENABLE_SHA384
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
#endif

#ifdef HASH_ENABLE_SHA512
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
#endif


TEST_SUITE_START (hash_riot);

TEST (hash_riot_test_init);
TEST (hash_riot_test_init_null);
TEST (hash_riot_test_release_null);
#ifdef HASH_ENABLE_SHA1
TEST (hash_riot_test_sha1_incremental);
TEST (hash_riot_test_sha1_incremental_multi);
TEST (hash_riot_test_sha1_incremental_full_hash_block);
TEST (hash_riot_test_sha1_incremental_update_to_full_hash_block);
TEST (hash_riot_test_sha1_incremental_multiple_hash_blocks_single_update);
TEST (hash_riot_test_sha1_incremental_multiple_hash_blocks_partial_update);
TEST (hash_riot_test_sha1_incremental_multiple_hash_blocks_not_aligned);
TEST (hash_riot_test_sha1_incremental_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_riot_test_sha1_incremental_partial_block_480_bits);
TEST (hash_riot_test_sha1_incremental_partial_block_448_bits);
TEST (hash_riot_test_sha1_incremental_partial_block_440_bits);
TEST (hash_riot_test_sha1_incremental_empty_hash_buffer);
TEST (hash_riot_test_sha1_incremental_after_finish);
TEST (hash_riot_test_sha1_incremental_cancel);
TEST (hash_riot_test_sha1_incremental_after_cancel);
TEST (hash_riot_test_sha1_start_incremental_null);
TEST (hash_riot_test_sha1_start_without_finish);
TEST (hash_riot_test_sha1_update_after_finish);
TEST (hash_riot_test_sha1_finish_after_finish);
TEST (hash_riot_test_sha1_finish_small_hash_buffer);
#endif
TEST (hash_riot_test_sha256_incremental);
TEST (hash_riot_test_sha256_incremental_multi);
TEST (hash_riot_test_sha256_incremental_full_hash_block);
TEST (hash_riot_test_sha256_incremental_update_to_full_hash_block);
TEST (hash_riot_test_sha256_incremental_multiple_hash_blocks_single_update);
TEST (hash_riot_test_sha256_incremental_multiple_hash_blocks_partial_update);
TEST (hash_riot_test_sha256_incremental_multiple_hash_blocks_not_aligned);
TEST (hash_riot_test_sha256_incremental_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_riot_test_sha256_incremental_partial_block_480_bits);
TEST (hash_riot_test_sha256_incremental_partial_block_448_bits);
TEST (hash_riot_test_sha256_incremental_partial_block_440_bits);
TEST (hash_riot_test_sha256_incremental_empty_hash_buffer);
TEST (hash_riot_test_sha256_incremental_after_finish);
TEST (hash_riot_test_sha256_incremental_cancel);
TEST (hash_riot_test_sha256_incremental_after_cancel);
TEST (hash_riot_test_sha256_start_incremental_null);
TEST (hash_riot_test_sha256_start_without_finish);
TEST (hash_riot_test_sha256_update_after_finish);
TEST (hash_riot_test_sha256_finish_after_finish);
TEST (hash_riot_test_sha256_finish_small_hash_buffer);
#ifdef HASH_ENABLE_SHA384
TEST (hash_riot_test_sha384_incremental);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (hash_riot_test_sha512_incremental);
#endif
TEST (hash_riot_test_incremental_update_null);
TEST (hash_riot_test_incremental_update_no_start);
TEST (hash_riot_test_incremental_finish_null);
TEST (hash_riot_test_incremental_finish_no_start);
TEST (hash_riot_test_incremental_cancel_null);
TEST (hash_riot_test_incremental_cancel_no_start);
#ifdef HASH_ENABLE_SHA1
TEST (hash_riot_test_calculate_sha1);
TEST (hash_riot_test_calculate_sha1_full_hash_block);
TEST (hash_riot_test_calculate_sha1_multiple_hash_blocks_not_aligned);
TEST (hash_riot_test_calculate_sha1_empty_hash_buffer);
TEST (hash_riot_test_calculate_sha1_null);
TEST (hash_riot_test_calculate_sha1_without_finish);
TEST (hash_riot_test_calculate_sha1_small_hash_buffer);
#endif
TEST (hash_riot_test_calculate_sha256);
TEST (hash_riot_test_calculate_sha256_full_hash_block);
TEST (hash_riot_test_calculate_sha256_multiple_hash_blocks_not_aligned);
TEST (hash_riot_test_calculate_sha256_empty_hash_buffer);
TEST (hash_riot_test_calculate_sha256_null);
TEST (hash_riot_test_calculate_sha256_without_finish);
TEST (hash_riot_test_calculate_sha256_small_hash_buffer);
#ifdef HASH_ENABLE_SHA384
TEST (hash_riot_test_calculate_sha384);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (hash_riot_test_calculate_sha512);
#endif

TEST_SUITE_END;
