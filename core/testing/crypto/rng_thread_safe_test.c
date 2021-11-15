// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/rng_thread_safe.h"
#include "testing/mock/crypto/rng_mock.h"


TEST_SUITE_LABEL ("rng_thread_safe");


/*******************
 * Test cases
 *******************/

static void rng_thread_safe_test_init (CuTest *test)
{
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.generate_random_buffer);

	status = rng_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	rng_thread_safe_release (&engine);
}

static void rng_thread_safe_test_init_null (CuTest *test)
{
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (NULL, &mock.base);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_thread_safe_init (&engine, NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void rng_thread_safe_test_release_null (CuTest *test)
{
	TEST_START;

	rng_thread_safe_release (NULL);
}

static void rng_thread_safe_test_generate_random_buffer (CuTest *test)
{
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;
	uint8_t buffer[32];

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.generate_random_buffer, &mock, 0, MOCK_ARG (32),
		MOCK_ARG (buffer));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_random_buffer (&engine.base, 32, buffer);

	rng_mock_release (&mock);
	rng_thread_safe_release (&engine);
}

static void rng_thread_safe_test_generate_random_buffer_error (CuTest *test)
{
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;
	uint8_t buffer[32];

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.generate_random_buffer, &mock,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (32), MOCK_ARG (buffer));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_random_buffer (&engine.base, 32, buffer);

	rng_mock_release (&mock);
	rng_thread_safe_release (&engine);
}

static void rng_thread_safe_test_generate_random_buffer_null (CuTest *test)
{
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;
	uint8_t buffer[32];

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (NULL, 32, buffer);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.generate_random_buffer (&engine.base, 32, buffer);

	rng_mock_release (&mock);
	rng_thread_safe_release (&engine);
}


TEST_SUITE_START (rng_thread_safe);

TEST (rng_thread_safe_test_init);
TEST (rng_thread_safe_test_init_null);
TEST (rng_thread_safe_test_release_null);
TEST (rng_thread_safe_test_generate_random_buffer);
TEST (rng_thread_safe_test_generate_random_buffer_error);
TEST (rng_thread_safe_test_generate_random_buffer_null);

TEST_SUITE_END;
