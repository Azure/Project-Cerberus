// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/rng_mbedtls.h"


static const char *SUITE = "rng_mbedtls";


/*******************
 * Test cases
 *******************/

static void rng_mbedtls_test_init (CuTest *test)
{
	struct rng_engine_mbedtls engine;
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.generate_random_buffer);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = rng_mbedtls_init (NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);
}

static void rng_mbedtls_test_release_null (CuTest *test)
{
	TEST_START;

	rng_mbedtls_release (NULL);
}

static void rng_mbedtls_test_release_no_init (CuTest *test)
{
	struct rng_engine_mbedtls engine;

	TEST_START;

	memset (&engine, 0, sizeof (engine));
	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_generate_random_buffer (CuTest *test)
{
	struct rng_engine_mbedtls engine;
	uint8_t buffer [32];
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, buffer);
	CuAssertIntEquals (test, 0, status);

	rng_mbedtls_release (&engine);
}

static void rng_mbedtls_test_generate_random_buffer_twice (CuTest *test)
{
	struct rng_engine_mbedtls engine;
	uint8_t buffer[32];
	uint8_t buffer2[32];
	int i_buffer;
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine);
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

static void rng_mbedtls_test_generate_random_buffer_null (CuTest *test)
{
	struct rng_engine_mbedtls engine;
	uint8_t buffer [32];
	int status;

	TEST_START;

	status = rng_mbedtls_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.generate_random_buffer (NULL, 32, buffer);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.generate_random_buffer (&engine.base, 32, NULL);
	CuAssertIntEquals (test, RNG_ENGINE_INVALID_ARGUMENT, status);

	rng_mbedtls_release (&engine);
}


CuSuite* get_rng_mbedtls_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, rng_mbedtls_test_init);
	SUITE_ADD_TEST (suite, rng_mbedtls_test_init_null);
	SUITE_ADD_TEST (suite, rng_mbedtls_test_release_null);
	SUITE_ADD_TEST (suite, rng_mbedtls_test_release_no_init);
	SUITE_ADD_TEST (suite, rng_mbedtls_test_generate_random_buffer);
	SUITE_ADD_TEST (suite, rng_mbedtls_test_generate_random_buffer_twice);
	SUITE_ADD_TEST (suite, rng_mbedtls_test_generate_random_buffer_null);

	return suite;
}
