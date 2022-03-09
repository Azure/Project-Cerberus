// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/rng_dummy.h"


TEST_SUITE_LABEL ("rng_dummy");


/*******************
 * Test cases
 *******************/

static void rng_dummy_test_init (CuTest *test)
{
	struct rng_engine_dummy engine;
	int status;

	TEST_START;

	status = rng_dummy_init (&engine, 0x100);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.generate_random_buffer);

	rng_dummy_release (&engine);
}

static void rng_dummy_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = rng_dummy_init (NULL, 0x100);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);
}

static void rng_dummy_test_release_null (CuTest *test)
{
	TEST_START;

	rng_dummy_release (NULL);
}

static void rng_dummy_test_generate_random_buffer (CuTest *test)
{
	struct rng_engine_dummy engine;
	uint8_t buffer[32] = {0};
	uint8_t zero[32] = {0};
	int status;

	TEST_START;

	status = rng_dummy_init (&engine, 0x100);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertTrue (test, (status != 0));

	rng_dummy_release (&engine);
}

static void rng_dummy_test_generate_random_buffer_not_word_aligned (CuTest *test)
{
	struct rng_engine_dummy engine;
	uint8_t buffer[13] = {0};
	uint8_t pad[4] = {0};
	uint8_t zero[13] = {0};
	int status;

	TEST_START;

	status = rng_dummy_init (&engine, 0x100);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 13, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertTrue (test, (status != 0));

	status = testing_validate_array (zero, pad, sizeof (pad));
	CuAssertIntEquals (test, 0, status);

	rng_dummy_release (&engine);
}

static void rng_dummy_test_generate_random_buffer_start_not_word_aligned (CuTest *test)
{
	struct rng_engine_dummy engine;
	uint8_t buffer[14] = {0};
	uint8_t pad[4] = {0};
	uint8_t zero[14] = {0};
	uint8_t *out = &buffer[1];
	int status;

	TEST_START;

	CuAssertTrue (test, (((uintptr_t) out & 0x3) != 0));

	status = rng_dummy_init (&engine, 0x100);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 12, out);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, &buffer[1], sizeof (buffer) - 1);
	CuAssertTrue (test, (status != 0));

	status = testing_validate_array (zero, pad, sizeof (pad));
	CuAssertIntEquals (test, 0, status);

	rng_dummy_release (&engine);
}

static void rng_dummy_test_generate_random_buffer_twice (CuTest *test)
{
	struct rng_engine_dummy engine;
	uint8_t buffer[32];
	uint8_t buffer2[32];
	int i_buffer;
	int status;

	TEST_START;

	status = rng_dummy_init (&engine, 0x100);
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

	rng_dummy_release (&engine);
}

static void rng_dummy_test_generate_random_buffer_no_data (CuTest *test)
{
	struct rng_engine_dummy engine;
	uint8_t buffer[32] = {0};
	uint8_t zero[32] = {0};
	int status;

	TEST_START;

	status = rng_dummy_init (&engine, 0x100);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 0, buffer);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (zero, buffer, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);

	rng_dummy_release (&engine);
}

static void rng_dummy_test_generate_random_buffer_null (CuTest *test)
{
	struct rng_engine_dummy engine;
	uint8_t buffer[32];
	int status;

	TEST_START;

	status = rng_dummy_init (&engine, 0x100);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (NULL, 32, buffer);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	rng_dummy_release (&engine);
}


TEST_SUITE_START (rng_dummy);

TEST (rng_dummy_test_init);
TEST (rng_dummy_test_init_null);
TEST (rng_dummy_test_release_null);
TEST (rng_dummy_test_generate_random_buffer);
TEST (rng_dummy_test_generate_random_buffer_not_word_aligned);
TEST (rng_dummy_test_generate_random_buffer_start_not_word_aligned);
TEST (rng_dummy_test_generate_random_buffer_twice);
TEST (rng_dummy_test_generate_random_buffer_no_data);
TEST (rng_dummy_test_generate_random_buffer_null);

TEST_SUITE_END;
