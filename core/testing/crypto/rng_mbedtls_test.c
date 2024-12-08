// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "crypto/rng_mbedtls.h"
#include "crypto/rng_mbedtls_static.h"
#include "testing/crypto/hash_testing.h"
#include "testing/mock/crypto/rng_mock.h"


TEST_SUITE_LABEL ("rng_mbedtls");


/*******************
 * Test cases
 *******************/

static void rng_mbedtls_test_init (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine;
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.generate_random_buffer);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_init_null (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine;
	int status;

	TEST_START;

	status = rng_mbedtls_init (NULL, &state);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_mbedtls_init (&engine, NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);
}

static void rng_mbedtls_test_static_init (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine = rng_mbedtls_static_init (&state);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, engine.base.generate_random_buffer);

	status = rng_mbedtls_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_static_init_null (CuTest *test)
{
	struct rng_engine_mbedtls null_state = rng_mbedtls_static_init (NULL);
	int status;

	TEST_START;

	status = rng_mbedtls_init_state (NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_mbedtls_init_state (&null_state);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);
}

static void rng_mbedtls_test_release_null (CuTest *test)
{
	TEST_START;

	rng_mbedtls_release (NULL);
}

static void rng_mbedtls_test_generate_random_buffer (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine;
	uint8_t buffer[32] = {0};
	uint8_t zero[32] = {0};
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertTrue (test, (status != 0));

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_generate_random_buffer_not_word_aligned (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine;
	uint8_t buffer[13] = {0};
	uint8_t pad[4] = {0};
	uint8_t zero[13] = {0};
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 13, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertTrue (test, (status != 0));

	status = testing_validate_array (zero, pad, sizeof (pad));
	CuAssertIntEquals (test, 0, status);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_generate_random_buffer_start_not_word_aligned (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine;
	uint8_t buffer[14] = {0};
	uint8_t pad[4] = {0};
	uint8_t zero[14] = {0};
	uint8_t *out = &buffer[1];
	int status;

	TEST_START;

	CuAssertTrue (test, (((uintptr_t) out & 0x3) != 0));

	status = rng_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 12, out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, &buffer[1], sizeof (buffer) - 1);
	CuAssertTrue (test, (status != 0));

	status = testing_validate_array (zero, pad, sizeof (pad));
	CuAssertIntEquals (test, 0, status);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_generate_random_buffer_twice (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine;
	uint8_t buffer[32];
	uint8_t buffer2[32];
	int i_buffer;
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer2);
	CuAssertIntEquals (test, 0, status);

	for (i_buffer = 0; i_buffer < 32; ++i_buffer) {
		if (buffer[i_buffer] != buffer2[i_buffer]) {
			break;
		}
	}

	CuAssertTrue (test, i_buffer != 32);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_generate_random_buffer_no_data (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine;
	uint8_t buffer[32] = {0};
	uint8_t zero[32] = {0};
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 0, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_generate_random_buffer_static_init (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine = rng_mbedtls_static_init (&state);
	uint8_t buffer[32] = {0};
	uint8_t zero[32] = {0};
	int status;

	TEST_START;

	status = rng_mbedtls_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertTrue (test, (status != 0));

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_generate_random_buffer_null (CuTest *test)
{
	struct rng_engine_mbedtls_state state;
	struct rng_engine_mbedtls engine;
	uint8_t buffer[32];
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine, &state);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (NULL, 32, buffer);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_rng_callback (CuTest *test)
{
	struct rng_engine_mock engine;
	int status;
	uint8_t output[16] = {0};

	TEST_START;

	status = rng_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.generate_random_buffer, &engine, 0,
		MOCK_ARG (sizeof (output)), MOCK_ARG_PTR (output));
	status |= mock_expect_output (&engine.mock, 1, HASH_TESTING_FULL_BLOCK_512,
		HASH_TESTING_FULL_BLOCK_512_LEN, 0);

	CuAssertIntEquals (test, 0, status);

	status = rng_mbedtls_rng_callback (&engine.base, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (HASH_TESTING_FULL_BLOCK_512, output, sizeof (output));
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void rng_mbedtls_test_rng_callback_null (CuTest *test)
{
	struct rng_engine_mock engine;
	int status;
	uint8_t output[16] = {0};

	TEST_START;

	status = rng_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = rng_mbedtls_rng_callback (NULL, output, sizeof (output));
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_mbedtls_rng_callback (&engine.base, NULL, sizeof (output));
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}

static void rng_mbedtls_test_rng_callback_error (CuTest *test)
{
	struct rng_engine_mock engine;
	int status;
	uint8_t output[16] = {0};

	TEST_START;

	status = rng_mock_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&engine.mock, engine.base.generate_random_buffer, &engine,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (sizeof (output)), MOCK_ARG_PTR (output));

	CuAssertIntEquals (test, 0, status);

	status = rng_mbedtls_rng_callback (&engine.base, output, sizeof (output));
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	status = rng_mock_validate_and_release (&engine);
	CuAssertIntEquals (test, 0, status);
}


// *INDENT-OFF*
TEST_SUITE_START (rng_mbedtls);

TEST (rng_mbedtls_test_init);
TEST (rng_mbedtls_test_init_null);
TEST (rng_mbedtls_test_static_init);
TEST (rng_mbedtls_test_static_init_null);
TEST (rng_mbedtls_test_release_null);
TEST (rng_mbedtls_test_generate_random_buffer);
TEST (rng_mbedtls_test_generate_random_buffer_not_word_aligned);
TEST (rng_mbedtls_test_generate_random_buffer_start_not_word_aligned);
TEST (rng_mbedtls_test_generate_random_buffer_twice);
TEST (rng_mbedtls_test_generate_random_buffer_no_data);
TEST (rng_mbedtls_test_generate_random_buffer_static_init);
TEST (rng_mbedtls_test_generate_random_buffer_null);
TEST (rng_mbedtls_test_rng_callback);
TEST (rng_mbedtls_test_rng_callback_null);
TEST (rng_mbedtls_test_rng_callback_error);

TEST_SUITE_END;
// *INDENT-ON*
