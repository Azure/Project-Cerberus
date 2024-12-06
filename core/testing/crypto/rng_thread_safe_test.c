// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "crypto/rng_thread_safe.h"
#include "crypto/rng_thread_safe_static.h"
#include "testing/mock/crypto/rng_mock.h"


TEST_SUITE_LABEL ("rng_thread_safe");


/*******************
 * Test cases
 *******************/

static void rng_thread_safe_test_init (CuTest *test)
{
	struct rng_engine_thread_safe_state state;
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.generate_random_buffer);

	status = rng_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	rng_thread_safe_release (&engine);
}

static void rng_thread_safe_test_init_null (CuTest *test)
{
	struct rng_engine_thread_safe_state state;
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (NULL, &state, &mock.base);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_thread_safe_init (&engine, NULL, &mock.base);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_thread_safe_init (&engine, &state, NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void rng_thread_safe_test_static_init (CuTest *test)
{
	struct rng_engine_mock mock;
	struct rng_engine_thread_safe_state state;
	struct rng_engine_thread_safe engine = rng_thread_safe_static_init (&state, &mock.base);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, engine.base.generate_random_buffer);

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	rng_thread_safe_release (&engine);
}

static void rng_thread_safe_test_static_init_null (CuTest *test)
{
	struct rng_engine_mock mock;
	struct rng_engine_thread_safe_state state;
	struct rng_engine_thread_safe null_state = rng_thread_safe_static_init (NULL, &mock.base);
	struct rng_engine_thread_safe null_target = rng_thread_safe_static_init (&state, NULL);
	int status;

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init_state (NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_thread_safe_init_state (&null_state);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = rng_thread_safe_init_state (&null_target);
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
	struct rng_engine_thread_safe_state state;
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;
	uint8_t buffer[32];

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.generate_random_buffer, &mock, 0, MOCK_ARG (32),
		MOCK_ARG_PTR (buffer));
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

static void rng_thread_safe_test_generate_random_buffer_static_init (CuTest *test)
{
	struct rng_engine_mock mock;
	struct rng_engine_thread_safe_state state;
	struct rng_engine_thread_safe engine = rng_thread_safe_static_init (&state, &mock.base);
	int status;
	uint8_t buffer[32];

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init_state (&engine);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.generate_random_buffer, &mock, 0, MOCK_ARG (32),
		MOCK_ARG_PTR (buffer));
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
	struct rng_engine_thread_safe_state state;
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;
	uint8_t buffer[32];

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (&engine, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.generate_random_buffer, &mock,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (32), MOCK_ARG_PTR (buffer));
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
	struct rng_engine_thread_safe_state state;
	struct rng_engine_thread_safe engine;
	struct rng_engine_mock mock;
	int status;
	uint8_t buffer[32];

	TEST_START;

	status = rng_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = rng_thread_safe_init (&engine, &state, &mock.base);
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


// *INDENT-OFF*
TEST_SUITE_START (rng_thread_safe);

TEST (rng_thread_safe_test_init);
TEST (rng_thread_safe_test_init_null);
TEST (rng_thread_safe_test_static_init);
TEST (rng_thread_safe_test_static_init_null);
TEST (rng_thread_safe_test_release_null);
TEST (rng_thread_safe_test_generate_random_buffer);
TEST (rng_thread_safe_test_generate_random_buffer_static_init);
TEST (rng_thread_safe_test_generate_random_buffer_error);
TEST (rng_thread_safe_test_generate_random_buffer_null);

TEST_SUITE_END;
// *INDENT-ON*
