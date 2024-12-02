// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "crypto/hash_mbedtls.h"
#include "testing/crypto/hash_testing.h"


TEST_SUITE_LABEL ("hash_mbedtls");


/*******************
 * Test cases
 *******************/

static void hash_mbedtls_test_init (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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
	CuAssertPtrNotNull (test, engine.base.get_hash);
	CuAssertPtrNotNull (test, engine.base.finish);
	CuAssertPtrNotNull (test, engine.base.cancel);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_init_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;

	TEST_START;

	status = hash_mbedtls_init (NULL, &state);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = hash_mbedtls_init (&engine, NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);
}

static void hash_mbedtls_test_release_null (CuTest *test)
{
	TEST_START;

	hash_mbedtls_release (NULL);
}

#ifdef HASH_ENABLE_SHA1
static void hash_mbedtls_test_sha1_incremental (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_multi (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_update_to_full_hash_block_after_full_block (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_1024, SHA1_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_1024[SHA1_BLOCK_SIZE + (i * (SHA1_BLOCK_SIZE / 4))],
			SHA1_BLOCK_SIZE / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_multiple_hash_blocks_single_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_multiple_hash_blocks_partial_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_partial_block_480_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_partial_block_448_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_partial_block_440_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_512[i * (HASH_TESTING_FULL_BLOCK_512_LEN / 4)],
			HASH_TESTING_FULL_BLOCK_512_LEN / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_update_to_full_hash_block_after_full_block (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_1024, SHA1_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_1024[SHA1_BLOCK_SIZE + (i * (SHA1_BLOCK_SIZE / 4))],
			SHA1_BLOCK_SIZE / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_multiple_hash_blocks_single_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_2048_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_multiple_hash_blocks_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_FULL_BLOCK_2048[8],
		HASH_TESTING_FULL_BLOCK_2048_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_multiple_hash_blocks_not_aligned (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void
hash_mbedtls_test_sha1_incremental_get_hash_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[8],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_partial_block_480_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_480,
		HASH_TESTING_PARTIAL_BLOCK_480_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_480_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_480_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_partial_block_448_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_448,
		HASH_TESTING_PARTIAL_BLOCK_448_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_448_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_448_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_partial_block_440_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_440,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_440_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_PARTIAL_BLOCK_440_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_get_hash_without_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_cancel (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_incremental_after_cancel (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_start_incremental_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_start_without_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_update_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_finish_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_get_hash_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha1_get_hash_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha1 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}
#endif

static void hash_mbedtls_test_sha256_incremental (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_multi (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_update_to_full_hash_block_after_full_block (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_1024, SHA256_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_1024[SHA256_BLOCK_SIZE + (i * (SHA256_BLOCK_SIZE / 4))],
			SHA256_BLOCK_SIZE / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_multiple_hash_blocks_single_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_multiple_hash_blocks_partial_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_partial_block_480_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_partial_block_448_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_partial_block_440_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_512[i * (HASH_TESTING_FULL_BLOCK_512_LEN / 4)],
			HASH_TESTING_FULL_BLOCK_512_LEN / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_update_to_full_hash_block_after_full_block
(
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_1024, SHA256_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_1024[SHA256_BLOCK_SIZE + (i * (SHA256_BLOCK_SIZE / 4))],
			SHA256_BLOCK_SIZE / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_multiple_hash_blocks_single_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_2048_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_multiple_hash_blocks_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_FULL_BLOCK_2048[8],
		HASH_TESTING_FULL_BLOCK_2048_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_multiple_hash_blocks_not_aligned (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void
hash_mbedtls_test_sha256_incremental_get_hash_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[8],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_partial_block_480_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_480,
		HASH_TESTING_PARTIAL_BLOCK_480_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_480_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_480_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_partial_block_448_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_448,
		HASH_TESTING_PARTIAL_BLOCK_448_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_448_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_448_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_partial_block_440_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_440,
		HASH_TESTING_PARTIAL_BLOCK_440_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_440_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_PARTIAL_BLOCK_440_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_get_hash_without_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_cancel (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_incremental_after_cancel (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_start_incremental_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_start_without_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_update_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_finish_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_get_hash_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha256_get_hash_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

#ifdef HASH_ENABLE_SHA384
static void hash_mbedtls_test_sha384_incremental (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_multi (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_1024[i * (HASH_TESTING_FULL_BLOCK_1024_LEN / 4)],
			HASH_TESTING_FULL_BLOCK_1024_LEN / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_update_to_full_hash_block_after_full_block (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048, SHA384_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_2048[SHA384_BLOCK_SIZE + (i * (SHA384_BLOCK_SIZE / 4))],
			SHA384_BLOCK_SIZE / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_multiple_hash_blocks_single_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_4096,
		HASH_TESTING_FULL_BLOCK_4096_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_multiple_hash_blocks_partial_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_4096, 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_FULL_BLOCK_4096[16],
		HASH_TESTING_FULL_BLOCK_4096_LEN - 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[16],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_partial_block_992_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_992,
		HASH_TESTING_PARTIAL_BLOCK_992_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_992_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_partial_block_960_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_960,
		HASH_TESTING_PARTIAL_BLOCK_960_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_960_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_partial_block_952_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_952,
		HASH_TESTING_PARTIAL_BLOCK_952_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_952_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_1024[i * (HASH_TESTING_FULL_BLOCK_1024_LEN / 4)],
			HASH_TESTING_FULL_BLOCK_1024_LEN / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_update_to_full_hash_block_after_full_block
(
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048, SHA384_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_2048[SHA384_BLOCK_SIZE + (i * (SHA384_BLOCK_SIZE / 4))],
			SHA384_BLOCK_SIZE / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_multiple_hash_blocks_single_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_4096,
		HASH_TESTING_FULL_BLOCK_4096_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_multiple_hash_blocks_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_4096, 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_FULL_BLOCK_4096[16],
		HASH_TESTING_FULL_BLOCK_4096_LEN - 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_multiple_hash_blocks_not_aligned (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void
hash_mbedtls_test_sha384_incremental_get_hash_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[16],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_partial_block_992_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_992,
		HASH_TESTING_PARTIAL_BLOCK_992_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_992_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_992_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_partial_block_960_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_960,
		HASH_TESTING_PARTIAL_BLOCK_960_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_960_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_960_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_partial_block_952_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_952,
		HASH_TESTING_PARTIAL_BLOCK_952_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_952_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_PARTIAL_BLOCK_952_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_get_hash_without_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_cancel (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_incremental_after_cancel (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);

	engine.base.cancel (&engine.base);

	/* Run a new hash to see that it is calculated correctly. */
	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[8],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_start_incremental_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_start_without_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_IN_PROGRESS, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_update_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_finish_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_get_hash_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	status = testing_validate_array (SHA384_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha384_get_hash_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void hash_mbedtls_test_sha512_incremental (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_multi (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_1024[i * (HASH_TESTING_FULL_BLOCK_1024_LEN / 4)],
			HASH_TESTING_FULL_BLOCK_1024_LEN / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_update_to_full_hash_block_after_full_block (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048, SHA512_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_2048[SHA512_BLOCK_SIZE + (i * (SHA512_BLOCK_SIZE / 4))],
			SHA512_BLOCK_SIZE / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_multiple_hash_blocks_single_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_4096,
		HASH_TESTING_FULL_BLOCK_4096_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_multiple_hash_blocks_partial_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_4096, 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_FULL_BLOCK_4096[16],
		HASH_TESTING_FULL_BLOCK_4096_LEN - 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[16],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_partial_block_992_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_992,
		HASH_TESTING_PARTIAL_BLOCK_992_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_992_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_partial_block_960_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_960,
		HASH_TESTING_PARTIAL_BLOCK_960_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_960_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_partial_block_952_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_952,
		HASH_TESTING_PARTIAL_BLOCK_952_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_952_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_update_to_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_1024[i * (HASH_TESTING_FULL_BLOCK_1024_LEN / 4)],
			HASH_TESTING_FULL_BLOCK_1024_LEN / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_update_to_full_hash_block_after_full_block
(
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];
	int i;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_2048, SHA512_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < 4; i++) {
		status = engine.base.update (&engine.base,
			&HASH_TESTING_FULL_BLOCK_2048[SHA512_BLOCK_SIZE + (i * (SHA512_BLOCK_SIZE / 4))],
			SHA512_BLOCK_SIZE / 4);
		CuAssertIntEquals (test, 0, status);
	}

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_2048_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_multiple_hash_blocks_single_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_4096,
		HASH_TESTING_FULL_BLOCK_4096_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_multiple_hash_blocks_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_FULL_BLOCK_4096, 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_FULL_BLOCK_4096[16],
		HASH_TESTING_FULL_BLOCK_4096_LEN - 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_4096_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_multiple_hash_blocks_not_aligned (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void
hash_mbedtls_test_sha512_incremental_get_hash_multiple_hash_blocks_not_aligned_partial_update (
	CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[16],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 16);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_partial_block_992_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_992,
		HASH_TESTING_PARTIAL_BLOCK_992_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_992_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_992_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_partial_block_960_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_960,
		HASH_TESTING_PARTIAL_BLOCK_960_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_960_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_960_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_partial_block_952_bits (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_PARTIAL_BLOCK_952,
		HASH_TESTING_PARTIAL_BLOCK_952_LEN);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_952_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	memset (hash, 0, sizeof (hash));

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_PARTIAL_BLOCK_952_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_get_hash_without_update (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_cancel (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_incremental_after_cancel (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN);

	engine.base.cancel (&engine.base);

	/* Run a new hash to see that it is calculated correctly. */
	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED, 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, &HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED[8],
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN - 8);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_start_incremental_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (NULL);
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_start_without_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_IN_PROGRESS, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_update_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_finish_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_get_hash_after_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_finish_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	status = testing_validate_array (SHA512_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_sha512_get_hash_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash) - 1);
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}
#endif

static void hash_mbedtls_test_incremental_update_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (NULL, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.update (&engine.base, NULL, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_incremental_update_no_start (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_incremental_finish_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (NULL, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.finish (&engine.base, NULL, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_incremental_finish_no_start (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_incremental_cancel_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (NULL);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_incremental_cancel_no_start (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	engine.base.cancel (&engine.base);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_incremental_get_hash_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha256 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (NULL, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.get_hash (&engine.base, NULL, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_incremental_get_hash_no_start (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.get_hash (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_NO_ACTIVE_HASH, status);

	hash_mbedtls_release (&engine);
}

#ifdef HASH_ENABLE_SHA1
static void hash_mbedtls_test_calculate_sha1 (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha1_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha1_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha1_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA1_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha1_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (NULL, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha1 (&engine.base, NULL, strlen (message), hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), NULL,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_INVALID_ARGUMENT, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha1_without_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha1_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA1_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha1 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_mbedtls_release (&engine);
}
#endif

static void hash_mbedtls_test_calculate_sha256 (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha256_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_FULL_BLOCK_512_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha256_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha256_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA256_EMPTY_BUFFER_HASH, hash, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha256_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha256_without_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha256_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA256_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha256 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_mbedtls_release (&engine);
}

#ifdef HASH_ENABLE_SHA384
static void hash_mbedtls_test_calculate_sha384 (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha384_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha384_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha384_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha384_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha384_without_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha384 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));

	status = engine.base.calculate_sha384 (&engine.base, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_2048_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_IN_PROGRESS, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA384_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha384_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA384_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha384 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_mbedtls_release (&engine);
}
#endif

#ifdef HASH_ENABLE_SHA512
static void hash_mbedtls_test_calculate_sha512 (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha512_full_hash_block (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, HASH_TESTING_FULL_BLOCK_1024,
		HASH_TESTING_FULL_BLOCK_1024_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_FULL_BLOCK_1024_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha512_multiple_hash_blocks_not_aligned (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED,
		HASH_TESTING_MULTI_BLOCK_NOT_ALIGNED_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_MULTI_BLOCK_NOT_ALIGNED_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha512_empty_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, NULL, 0, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_EMPTY_BUFFER_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha512_null (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
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

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha512_without_finish (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.start_sha512 (&engine.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));

	status = engine.base.calculate_sha512 (&engine.base, HASH_TESTING_FULL_BLOCK_2048,
		HASH_TESTING_FULL_BLOCK_2048_LEN, hash, sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_IN_PROGRESS, status);

	status = engine.base.update (&engine.base, (uint8_t*) message, strlen (message));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.finish (&engine.base, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (SHA512_TEST_TEST_HASH, hash, sizeof (hash));
	CuAssertIntEquals (test, 0, status);

	hash_mbedtls_release (&engine);
}

static void hash_mbedtls_test_calculate_sha512_small_hash_buffer (CuTest *test)
{
	struct hash_engine_mbedtls_state state;
	struct hash_engine_mbedtls engine;
	int status;
	char *message = "Test";
	uint8_t hash[SHA512_HASH_LENGTH - 1];

	TEST_START;

	status = hash_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.calculate_sha512 (&engine.base, (uint8_t*) message, strlen (message), hash,
		sizeof (hash));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	hash_mbedtls_release (&engine);
}
#endif


// *INDENT-OFF*
TEST_SUITE_START (hash_mbedtls);

TEST (hash_mbedtls_test_init);
TEST (hash_mbedtls_test_init_null);
TEST (hash_mbedtls_test_release_null);
#ifdef HASH_ENABLE_SHA1
TEST (hash_mbedtls_test_sha1_incremental);
TEST (hash_mbedtls_test_sha1_incremental_multi);
TEST (hash_mbedtls_test_sha1_incremental_full_hash_block);
TEST (hash_mbedtls_test_sha1_incremental_update_to_full_hash_block);
TEST (hash_mbedtls_test_sha1_incremental_update_to_full_hash_block_after_full_block);
TEST (hash_mbedtls_test_sha1_incremental_multiple_hash_blocks_single_update);
TEST (hash_mbedtls_test_sha1_incremental_multiple_hash_blocks_partial_update);
TEST (hash_mbedtls_test_sha1_incremental_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_sha1_incremental_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_mbedtls_test_sha1_incremental_partial_block_480_bits);
TEST (hash_mbedtls_test_sha1_incremental_partial_block_448_bits);
TEST (hash_mbedtls_test_sha1_incremental_partial_block_440_bits);
TEST (hash_mbedtls_test_sha1_incremental_empty_hash_buffer);
TEST (hash_mbedtls_test_sha1_incremental_get_hash);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_full_hash_block);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_update_to_full_hash_block);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_update_to_full_hash_block_after_full_block);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_multiple_hash_blocks_single_update);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_multiple_hash_blocks_partial_update);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_partial_block_480_bits);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_partial_block_448_bits);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_partial_block_440_bits);
TEST (hash_mbedtls_test_sha1_incremental_get_hash_without_update);
TEST (hash_mbedtls_test_sha1_incremental_after_finish);
TEST (hash_mbedtls_test_sha1_incremental_cancel);
TEST (hash_mbedtls_test_sha1_incremental_after_cancel);
TEST (hash_mbedtls_test_sha1_start_incremental_null);
TEST (hash_mbedtls_test_sha1_start_without_finish);
TEST (hash_mbedtls_test_sha1_update_after_finish);
TEST (hash_mbedtls_test_sha1_finish_after_finish);
TEST (hash_mbedtls_test_sha1_get_hash_after_finish);
TEST (hash_mbedtls_test_sha1_finish_small_hash_buffer);
TEST (hash_mbedtls_test_sha1_get_hash_small_hash_buffer);
#endif
TEST (hash_mbedtls_test_sha256_incremental);
TEST (hash_mbedtls_test_sha256_incremental_multi);
TEST (hash_mbedtls_test_sha256_incremental_full_hash_block);
TEST (hash_mbedtls_test_sha256_incremental_update_to_full_hash_block);
TEST (hash_mbedtls_test_sha256_incremental_update_to_full_hash_block_after_full_block);
TEST (hash_mbedtls_test_sha256_incremental_multiple_hash_blocks_single_update);
TEST (hash_mbedtls_test_sha256_incremental_multiple_hash_blocks_partial_update);
TEST (hash_mbedtls_test_sha256_incremental_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_sha256_incremental_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_mbedtls_test_sha256_incremental_partial_block_480_bits);
TEST (hash_mbedtls_test_sha256_incremental_partial_block_448_bits);
TEST (hash_mbedtls_test_sha256_incremental_partial_block_440_bits);
TEST (hash_mbedtls_test_sha256_incremental_empty_hash_buffer);
TEST (hash_mbedtls_test_sha256_incremental_get_hash);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_full_hash_block);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_update_to_full_hash_block);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_update_to_full_hash_block_after_full_block);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_multiple_hash_blocks_single_update);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_multiple_hash_blocks_partial_update);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_partial_block_480_bits);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_partial_block_448_bits);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_partial_block_440_bits);
TEST (hash_mbedtls_test_sha256_incremental_get_hash_without_update);
TEST (hash_mbedtls_test_sha256_incremental_after_finish);
TEST (hash_mbedtls_test_sha256_incremental_cancel);
TEST (hash_mbedtls_test_sha256_incremental_after_cancel);
TEST (hash_mbedtls_test_sha256_start_incremental_null);
TEST (hash_mbedtls_test_sha256_start_without_finish);
TEST (hash_mbedtls_test_sha256_update_after_finish);
TEST (hash_mbedtls_test_sha256_finish_after_finish);
TEST (hash_mbedtls_test_sha256_get_hash_after_finish);
TEST (hash_mbedtls_test_sha256_finish_small_hash_buffer);
TEST (hash_mbedtls_test_sha256_get_hash_small_hash_buffer);
#ifdef HASH_ENABLE_SHA384
TEST (hash_mbedtls_test_sha384_incremental);
TEST (hash_mbedtls_test_sha384_incremental_multi);
TEST (hash_mbedtls_test_sha384_incremental_full_hash_block);
TEST (hash_mbedtls_test_sha384_incremental_update_to_full_hash_block);
TEST (hash_mbedtls_test_sha384_incremental_update_to_full_hash_block_after_full_block);
TEST (hash_mbedtls_test_sha384_incremental_multiple_hash_blocks_single_update);
TEST (hash_mbedtls_test_sha384_incremental_multiple_hash_blocks_partial_update);
TEST (hash_mbedtls_test_sha384_incremental_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_sha384_incremental_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_mbedtls_test_sha384_incremental_partial_block_992_bits);
TEST (hash_mbedtls_test_sha384_incremental_partial_block_960_bits);
TEST (hash_mbedtls_test_sha384_incremental_partial_block_952_bits);
TEST (hash_mbedtls_test_sha384_incremental_empty_hash_buffer);
TEST (hash_mbedtls_test_sha384_incremental_get_hash);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_full_hash_block);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_update_to_full_hash_block);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_update_to_full_hash_block_after_full_block);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_multiple_hash_blocks_single_update);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_multiple_hash_blocks_partial_update);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_partial_block_992_bits);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_partial_block_960_bits);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_partial_block_952_bits);
TEST (hash_mbedtls_test_sha384_incremental_get_hash_without_update);
TEST (hash_mbedtls_test_sha384_incremental_after_finish);
TEST (hash_mbedtls_test_sha384_incremental_cancel);
TEST (hash_mbedtls_test_sha384_incremental_after_cancel);
TEST (hash_mbedtls_test_sha384_start_incremental_null);
TEST (hash_mbedtls_test_sha384_start_without_finish);
TEST (hash_mbedtls_test_sha384_update_after_finish);
TEST (hash_mbedtls_test_sha384_finish_after_finish);
TEST (hash_mbedtls_test_sha384_get_hash_after_finish);
TEST (hash_mbedtls_test_sha384_finish_small_hash_buffer);
TEST (hash_mbedtls_test_sha384_get_hash_small_hash_buffer);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (hash_mbedtls_test_sha512_incremental);
TEST (hash_mbedtls_test_sha512_incremental_multi);
TEST (hash_mbedtls_test_sha512_incremental_full_hash_block);
TEST (hash_mbedtls_test_sha512_incremental_update_to_full_hash_block);
TEST (hash_mbedtls_test_sha512_incremental_update_to_full_hash_block_after_full_block);
TEST (hash_mbedtls_test_sha512_incremental_multiple_hash_blocks_single_update);
TEST (hash_mbedtls_test_sha512_incremental_multiple_hash_blocks_partial_update);
TEST (hash_mbedtls_test_sha512_incremental_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_sha512_incremental_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_mbedtls_test_sha512_incremental_partial_block_992_bits);
TEST (hash_mbedtls_test_sha512_incremental_partial_block_960_bits);
TEST (hash_mbedtls_test_sha512_incremental_partial_block_952_bits);
TEST (hash_mbedtls_test_sha512_incremental_empty_hash_buffer);
TEST (hash_mbedtls_test_sha512_incremental_get_hash);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_full_hash_block);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_update_to_full_hash_block);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_update_to_full_hash_block_after_full_block);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_multiple_hash_blocks_single_update);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_multiple_hash_blocks_partial_update);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_multiple_hash_blocks_not_aligned_partial_update);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_partial_block_992_bits);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_partial_block_960_bits);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_partial_block_952_bits);
TEST (hash_mbedtls_test_sha512_incremental_get_hash_without_update);
TEST (hash_mbedtls_test_sha512_incremental_after_finish);
TEST (hash_mbedtls_test_sha512_incremental_cancel);
TEST (hash_mbedtls_test_sha512_incremental_after_cancel);
TEST (hash_mbedtls_test_sha512_start_incremental_null);
TEST (hash_mbedtls_test_sha512_start_without_finish);
TEST (hash_mbedtls_test_sha512_update_after_finish);
TEST (hash_mbedtls_test_sha512_finish_after_finish);
TEST (hash_mbedtls_test_sha512_get_hash_after_finish);
TEST (hash_mbedtls_test_sha512_finish_small_hash_buffer);
TEST (hash_mbedtls_test_sha512_get_hash_small_hash_buffer);
#endif
TEST (hash_mbedtls_test_incremental_update_null);
TEST (hash_mbedtls_test_incremental_update_no_start);
TEST (hash_mbedtls_test_incremental_finish_null);
TEST (hash_mbedtls_test_incremental_finish_no_start);
TEST (hash_mbedtls_test_incremental_cancel_null);
TEST (hash_mbedtls_test_incremental_cancel_no_start);
TEST (hash_mbedtls_test_incremental_get_hash_null);
TEST (hash_mbedtls_test_incremental_get_hash_no_start);
#ifdef HASH_ENABLE_SHA1
TEST (hash_mbedtls_test_calculate_sha1);
TEST (hash_mbedtls_test_calculate_sha1_full_hash_block);
TEST (hash_mbedtls_test_calculate_sha1_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_calculate_sha1_empty_hash_buffer);
TEST (hash_mbedtls_test_calculate_sha1_null);
TEST (hash_mbedtls_test_calculate_sha1_without_finish);
TEST (hash_mbedtls_test_calculate_sha1_small_hash_buffer);
#endif
TEST (hash_mbedtls_test_calculate_sha256);
TEST (hash_mbedtls_test_calculate_sha256_full_hash_block);
TEST (hash_mbedtls_test_calculate_sha256_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_calculate_sha256_empty_hash_buffer);
TEST (hash_mbedtls_test_calculate_sha256_null);
TEST (hash_mbedtls_test_calculate_sha256_without_finish);
TEST (hash_mbedtls_test_calculate_sha256_small_hash_buffer);
#ifdef HASH_ENABLE_SHA384
TEST (hash_mbedtls_test_calculate_sha384);
TEST (hash_mbedtls_test_calculate_sha384_full_hash_block);
TEST (hash_mbedtls_test_calculate_sha384_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_calculate_sha384_empty_hash_buffer);
TEST (hash_mbedtls_test_calculate_sha384_null);
TEST (hash_mbedtls_test_calculate_sha384_without_finish);
TEST (hash_mbedtls_test_calculate_sha384_small_hash_buffer);
#endif
#ifdef HASH_ENABLE_SHA512
TEST (hash_mbedtls_test_calculate_sha512);
TEST (hash_mbedtls_test_calculate_sha512_full_hash_block);
TEST (hash_mbedtls_test_calculate_sha512_multiple_hash_blocks_not_aligned);
TEST (hash_mbedtls_test_calculate_sha512_empty_hash_buffer);
TEST (hash_mbedtls_test_calculate_sha512_null);
TEST (hash_mbedtls_test_calculate_sha512_without_finish);
TEST (hash_mbedtls_test_calculate_sha512_small_hash_buffer);
#endif

TEST_SUITE_END;
// *INDENT-ON*
