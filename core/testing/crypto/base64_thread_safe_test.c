// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "crypto/base64_thread_safe.h"
#include "testing/mock/crypto/base64_mock.h"
#include "testing/crypto/base64_testing.h"


TEST_SUITE_LABEL ("base64_thread_safe");


/*******************
 * Test cases
 *******************/

static void base64_thread_safe_test_init (CuTest *test)
{
	struct base64_engine_thread_safe engine;
	struct base64_engine_mock mock;
	int status;

	TEST_START;

	status = base64_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = base64_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.encode);

	status = base64_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	base64_thread_safe_release (&engine);
}

static void base64_thread_safe_test_init_null (CuTest *test)
{
	struct base64_engine_thread_safe engine;
	struct base64_engine_mock mock;
	int status;

	TEST_START;

	status = base64_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = base64_thread_safe_init (NULL, &mock.base);
	CuAssertIntEquals (test, BASE64_ENGINE_INVALID_ARGUMENT, status);

	status = base64_thread_safe_init (&engine, NULL);
	CuAssertIntEquals (test, BASE64_ENGINE_INVALID_ARGUMENT, status);

	status = base64_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void base64_thread_safe_test_release_null (CuTest *test)
{
	TEST_START;

	base64_thread_safe_release (NULL);
}

static void base64_thread_safe_test_encode (CuTest *test)
{
	struct base64_engine_thread_safe engine;
	struct base64_engine_mock mock;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	status = base64_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = base64_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.encode, &mock, 0, MOCK_ARG (BASE64_DATA_BLOCK),
		MOCK_ARG (BASE64_DATA_BLOCK_LEN), MOCK_ARG (out), MOCK_ARG (sizeof (out)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out, sizeof (out));

	base64_mock_release (&mock);
	base64_thread_safe_release (&engine);
}

static void base64_thread_safe_test_encode_error (CuTest *test)
{
	struct base64_engine_thread_safe engine;
	struct base64_engine_mock mock;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	status = base64_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = base64_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&mock.mock, mock.base.encode, &mock, BASE64_ENGINE_ENCODE_FAILED,
		MOCK_ARG (BASE64_DATA_BLOCK), MOCK_ARG (BASE64_DATA_BLOCK_LEN), MOCK_ARG (out),
		MOCK_ARG (sizeof (out)));
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, BASE64_ENGINE_ENCODE_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out, sizeof (out));

	base64_mock_release (&mock);
	base64_thread_safe_release (&engine);
}

static void base64_thread_safe_test_encode_null (CuTest *test)
{
	struct base64_engine_thread_safe engine;
	struct base64_engine_mock mock;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	status = base64_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = base64_thread_safe_init (&engine, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (NULL, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, BASE64_ENGINE_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	/* Check lock has been released. */
	engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out, sizeof (out));

	base64_mock_release (&mock);
	base64_thread_safe_release (&engine);
}


TEST_SUITE_START (base64_thread_safe);

TEST (base64_thread_safe_test_init);
TEST (base64_thread_safe_test_init_null);
TEST (base64_thread_safe_test_release_null);
TEST (base64_thread_safe_test_encode);
TEST (base64_thread_safe_test_encode_error);
TEST (base64_thread_safe_test_encode_null);

TEST_SUITE_END;
