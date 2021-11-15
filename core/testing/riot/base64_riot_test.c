// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "riot/base64_riot.h"
#include "testing/crypto/base64_testing.h"


TEST_SUITE_LABEL ("base64_riot");


/*******************
 * Test cases
 *******************/

static void base64_riot_test_init (CuTest *test)
{
	struct base64_engine_riot engine;
	int status;

	TEST_START;

	status = base64_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, engine.base.encode);

	base64_riot_release (&engine);
}

static void base64_riot_test_init_null (CuTest *test)
{
	int status;

	TEST_START;

	status = base64_riot_init (NULL);
	CuAssertIntEquals (test, BASE64_ENGINE_INVALID_ARGUMENT, status);
}

static void base64_riot_test_release_null (CuTest *test)
{
	TEST_START;

	base64_riot_release (NULL);
}

static void base64_riot_test_encode (CuTest *test)
{
	struct base64_engine_riot engine;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	memset (out, 0xff, sizeof (out));

	status = base64_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BASE64_ENCODED_BLOCK_LEN, BASE64_LENGTH (BASE64_DATA_BLOCK_LEN));

	status = testing_validate_array (BASE64_ENCODED_BLOCK, out, BASE64_ENCODED_BLOCK_LEN);
	CuAssertIntEquals (test, 0, status);

	base64_riot_release (&engine);
}

static void base64_riot_test_encode_pad_one_byte (CuTest *test)
{
	struct base64_engine_riot engine;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	memset (out, 0xff, sizeof (out));

	status = base64_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN - 1, out,
		sizeof (out));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BASE64_ENCODED_PAD_ONE_LEN, BASE64_LENGTH (BASE64_DATA_BLOCK_LEN - 1));

	status = testing_validate_array (BASE64_ENCODED_PAD_ONE, out, BASE64_ENCODED_PAD_ONE_LEN);
	CuAssertIntEquals (test, 0, status);

	base64_riot_release (&engine);
}

static void base64_riot_test_encode_pad_two_bytes (CuTest *test)
{
	struct base64_engine_riot engine;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	memset (out, 0xff, sizeof (out));

	status = base64_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN - 2, out,
		sizeof (out));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BASE64_ENCODED_PAD_TWO_LEN, BASE64_LENGTH (BASE64_DATA_BLOCK_LEN - 2));

	status = testing_validate_array (BASE64_ENCODED_PAD_TWO, out, BASE64_ENCODED_PAD_TWO_LEN);
	CuAssertIntEquals (test, 0, status);

	base64_riot_release (&engine);
}

static void base64_riot_test_encode_not_multiple_of_4 (CuTest *test)
{
	struct base64_engine_riot engine;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	memset (out, 0xff, sizeof (out));

	status = base64_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN - 3, out,
		sizeof (out));
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, BASE64_ENCODED_THREE_LESS_LEN,
		BASE64_LENGTH (BASE64_DATA_BLOCK_LEN - 3));

	status = testing_validate_array (BASE64_ENCODED_THREE_LESS, out, BASE64_ENCODED_THREE_LESS_LEN);
	CuAssertIntEquals (test, 0, status);

	base64_riot_release (&engine);
}

static void base64_riot_test_encode_null (CuTest *test)
{
	struct base64_engine_riot engine;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	status = base64_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (NULL, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, BASE64_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.encode (&engine.base, NULL, BASE64_DATA_BLOCK_LEN, out,
		sizeof (out));
	CuAssertIntEquals (test, BASE64_ENGINE_INVALID_ARGUMENT, status);

	status = engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, NULL,
		sizeof (out));
	CuAssertIntEquals (test, BASE64_ENGINE_INVALID_ARGUMENT, status);

	base64_riot_release (&engine);
}

static void base64_riot_test_encode_buffer_too_small (CuTest *test)
{
	struct base64_engine_riot engine;
	int status;
	uint8_t out[BASE64_ENCODED_BLOCK_LEN * 2];

	TEST_START;

	status = base64_riot_init (&engine);
	CuAssertIntEquals (test, 0, status);

	status = engine.base.encode (&engine.base, BASE64_DATA_BLOCK, BASE64_DATA_BLOCK_LEN, out,
		BASE64_LENGTH (BASE64_DATA_BLOCK_LEN) - 1);
	CuAssertIntEquals (test, BASE64_ENGINE_ENC_BUFFER_TOO_SMALL, status);

	base64_riot_release (&engine);
}


TEST_SUITE_START (base64_riot);

TEST (base64_riot_test_init);
TEST (base64_riot_test_init_null);
TEST (base64_riot_test_release_null);
TEST (base64_riot_test_encode);
TEST (base64_riot_test_encode_pad_one_byte);
TEST (base64_riot_test_encode_pad_two_bytes);
TEST (base64_riot_test_encode_not_multiple_of_4);
TEST (base64_riot_test_encode_null);
TEST (base64_riot_test_encode_buffer_too_small);

TEST_SUITE_END;
