// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/buffer_util.h"


TEST_SUITE_LABEL ("buffer_util");


/*******************
 * Test cases
 *******************/

static void buffer_copy_full_buffer (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = 0;
	size_t length = sizeof (dest);
	size_t bytes;
	int status;

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	bytes = buffer_copy (src, sizeof (src), &offset, &length, dest);
	CuAssertIntEquals (test, sizeof (dest), bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, 0, length);

	status = testing_validate_array (src, dest, bytes);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_null_offset (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t length = sizeof (dest);
	size_t bytes;
	int status;

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	bytes = buffer_copy (src, sizeof (src), NULL, &length, dest);
	CuAssertIntEquals (test, sizeof (dest), bytes);
	CuAssertIntEquals (test, 0, length);

	status = testing_validate_array (src, dest, bytes);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_with_offset (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = 10;
	size_t length = sizeof (dest);
	size_t bytes;
	int status;

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	bytes = buffer_copy (src, sizeof (src), &offset, &length, dest);
	CuAssertIntEquals (test, sizeof (dest) - 10, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, 10, length);

	status = testing_validate_array (&src[10], dest, bytes);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_with_offset_same_as_source_length (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = sizeof (src);
	size_t length = sizeof (dest);
	size_t bytes;
	int status;
	uint8_t check[sizeof (dest)];

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	memcpy (check, dest, sizeof (check));

	bytes = buffer_copy (src, sizeof (src), &offset, &length, dest);
	CuAssertIntEquals (test, 0, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, sizeof (dest), length);

	status = testing_validate_array (check, dest, sizeof (dest));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_with_offset_longer_than_source (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = sizeof (src) + 1;
	size_t length = sizeof (dest);
	size_t bytes;
	int status;
	uint8_t check[sizeof (dest)];

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	memcpy (check, dest, sizeof (check));

	bytes = buffer_copy (src, sizeof (src), &offset, &length, dest);
	CuAssertIntEquals (test, 0, bytes);
	CuAssertIntEquals (test, 1, offset);
	CuAssertIntEquals (test, sizeof (dest), length);

	status = testing_validate_array (check, dest, sizeof (dest));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_small_buffer (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = 0;
	size_t length = sizeof (dest) - 10;
	size_t bytes;
	int status;

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	bytes = buffer_copy (src, sizeof (src), &offset, &length, dest);
	CuAssertIntEquals (test, sizeof (dest) - 10, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, 0, length);

	status = testing_validate_array (src, dest, bytes);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_null_length (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = 0;
	size_t bytes;
	int status;
	uint8_t check[sizeof (dest)];

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	memcpy (check, dest, sizeof (check));

	bytes = buffer_copy (src, sizeof (src), &offset, NULL, dest);
	CuAssertIntEquals (test, 0, bytes);
	CuAssertIntEquals (test, 0, offset);

	status = testing_validate_array (check, dest, sizeof (dest));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_zero_length (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = 0;
	size_t length = 0;
	size_t bytes;
	int status;
	uint8_t check[sizeof (dest)];

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	memcpy (check, dest, sizeof (check));

	bytes = buffer_copy (src, sizeof (src), &offset, NULL, dest);
	CuAssertIntEquals (test, 0, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, 0, length);

	status = testing_validate_array (check, dest, sizeof (dest));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_with_offset_small_buffer (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = 10;
	size_t length = 5;
	size_t bytes;
	int status;

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	bytes = buffer_copy (src, sizeof (src), &offset, &length, dest);
	CuAssertIntEquals (test, 5, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, 0, length);

	status = testing_validate_array (&src[10], dest, bytes);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_full_buffer_with_offset_small_buffer_past_source_end (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = 10;
	size_t length = sizeof (src) - 9;
	size_t bytes;
	int status;

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	bytes = buffer_copy (src, sizeof (src), &offset, &length, dest);
	CuAssertIntEquals (test, sizeof (src) - 10, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, 1, length);

	status = testing_validate_array (&src[10], dest, bytes);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_null_source (CuTest *test)
{
	uint8_t dest[32];
	size_t i;
	size_t offset = 0;
	size_t length = sizeof (dest);
	size_t bytes;
	int status;
	uint8_t check[sizeof (dest)];

	TEST_START;

	for (i = 0; i < sizeof (dest); i++) {
		dest[i] = ~i;
	}

	memcpy (check, dest, sizeof (check));

	bytes = buffer_copy (NULL, sizeof (dest), &offset, &length, dest);
	CuAssertIntEquals (test, 0, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, sizeof (dest), length);

	status = testing_validate_array (check, dest, sizeof (dest));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_zero_length_source (CuTest *test)
{
	uint8_t src[32];
	uint8_t dest[32];
	size_t i;
	size_t offset = 0;
	size_t length = sizeof (dest);
	size_t bytes;
	int status;
	uint8_t check[sizeof (dest)];

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
		dest[i] = ~i;
	}

	memcpy (check, dest, sizeof (check));

	bytes = buffer_copy (src, 0, &offset, &length, dest);
	CuAssertIntEquals (test, 0, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, sizeof (dest), length);

	status = testing_validate_array (check, dest, sizeof (dest));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_copy_null_destination (CuTest *test)
{
	uint8_t src[32];
	size_t i;
	size_t offset = 0;
	size_t length = sizeof (src);
	size_t bytes;

	TEST_START;

	for (i = 0; i < sizeof (src); i++) {
		src[i] = i;
	}

	bytes = buffer_copy (src, sizeof (src), &offset, &length, NULL);
	CuAssertIntEquals (test, 0, bytes);
	CuAssertIntEquals (test, 0, offset);
	CuAssertIntEquals (test, sizeof (src), length);
}


TEST_SUITE_START (buffer_util);

TEST (buffer_copy_full_buffer);
TEST (buffer_copy_full_buffer_null_offset);
TEST (buffer_copy_full_buffer_with_offset);
TEST (buffer_copy_full_buffer_with_offset_same_as_source_length);
TEST (buffer_copy_full_buffer_with_offset_longer_than_source);
TEST (buffer_copy_full_buffer_small_buffer);
TEST (buffer_copy_full_buffer_null_length);
TEST (buffer_copy_full_buffer_zero_length);
TEST (buffer_copy_full_buffer_with_offset_small_buffer);
TEST (buffer_copy_full_buffer_with_offset_small_buffer_past_source_end);
TEST (buffer_copy_null_source);
TEST (buffer_copy_zero_length_source);
TEST (buffer_copy_null_destination);

TEST_SUITE_END;
