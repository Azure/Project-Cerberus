// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/array_size.h"
#include "common/buffer_util.h"


TEST_SUITE_LABEL ("buffer_util");


/**
 * Data block containing sequential bytes to evaluate unaligned data access at different offsets.
 */
static const uint8_t BUFFER_TESTING_UNALIGNED_DATA[] = {
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};


/*******************
 * Test cases
 *******************/

static void buffer_copy_test_full_buffer (CuTest *test)
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

static void buffer_copy_test_full_buffer_null_offset (CuTest *test)
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

static void buffer_copy_test_full_buffer_with_offset (CuTest *test)
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

static void buffer_copy_test_full_buffer_with_offset_same_as_source_length (CuTest *test)
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

static void buffer_copy_test_full_buffer_with_offset_longer_than_source (CuTest *test)
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

static void buffer_copy_test_full_buffer_small_buffer (CuTest *test)
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

static void buffer_copy_test_full_buffer_null_length (CuTest *test)
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

static void buffer_copy_test_full_buffer_zero_length (CuTest *test)
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

static void buffer_copy_test_full_buffer_with_offset_small_buffer (CuTest *test)
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

static void buffer_copy_test_full_buffer_with_offset_small_buffer_past_source_end (CuTest *test)
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

static void buffer_copy_test_null_source (CuTest *test)
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

static void buffer_copy_test_zero_length_source (CuTest *test)
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

static void buffer_copy_test_null_destination (CuTest *test)
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

static void buffer_reverse_test_empty_buffer (CuTest *test)
{
	const size_t length = 0;
	uint8_t buffer[1];
	uint8_t reverse[1];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		reverse[j] = i;
	}

	buffer_reverse (buffer, length);

	status = testing_validate_array (reverse, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_test_single_byte (CuTest *test)
{
	const size_t length = 1;
	uint8_t buffer[length];
	uint8_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		reverse[j] = i;
	}

	buffer_reverse (buffer, length);

	status = testing_validate_array (reverse, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_test_even_byte_count (CuTest *test)
{
	const size_t length = 16;
	uint8_t buffer[length];
	uint8_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		reverse[j] = i;
	}

	buffer_reverse (buffer, length);

	status = testing_validate_array (reverse, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_test_odd_byte_count (CuTest *test)
{
	const size_t length = 21;
	uint8_t buffer[length];
	uint8_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		reverse[j] = i;
	}

	buffer_reverse (buffer, length);

	status = testing_validate_array (reverse, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_test_null (CuTest *test)
{
	TEST_START;

	buffer_reverse (NULL, 10);
}

static void buffer_are_overlapping_test_no_overlap_buf1_first (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = buf;
	uint8_t *buf2 = &buf[buf1_length];
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf1, buf1_length, buf2, buf2_length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_are_overlapping_test_no_overlap_buf2_first (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = buf;
	uint8_t *buf2 = &buf[buf1_length];
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf2, buf2_length, buf1, buf1_length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_are_overlapping_test_buf2_ends_in_buf1 (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = &buf[buf2_length];
	uint8_t *buf2 = &buf[1];
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf1, buf1_length, buf2, buf2_length);
	CuAssertIntEquals (test, 1, status);
}

static void buffer_are_overlapping_test_buf1_ends_in_buf2 (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = &buf[1];
	uint8_t *buf2 = &buf[buf1_length];
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf1, buf1_length, buf2, buf2_length);
	CuAssertIntEquals (test, 1, status);
}

static void buffer_are_overlapping_test_same_start_byte (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = buf;
	uint8_t *buf2 = buf;
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf1, buf1_length, buf2, buf2_length);
	CuAssertIntEquals (test, 1, status);
}

static void buffer_are_overlapping_test_buf2_within_buf1 (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = buf;
	uint8_t *buf2 = &buf[1];
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf1, buf1_length, buf2, buf2_length);
	CuAssertIntEquals (test, 1, status);
}

static void buffer_are_overlapping_test_buf1_within_buf2 (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = buf;
	uint8_t *buf2 = &buf[1];
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf2, buf2_length, buf1, buf1_length);
	CuAssertIntEquals (test, 1, status);
}

static void buffer_are_overlapping_test_buf2_starts_in_buf1 (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = buf;
	uint8_t *buf2 = &buf[buf1_length - 1];
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf1, buf1_length, buf2, buf2_length);
	CuAssertIntEquals (test, 1, status);
}

static void buffer_are_overlapping_test_buf1_starts_in_buf2 (CuTest *test)
{
	const size_t buf1_length = 32;
	const size_t buf2_length = 16;
	uint8_t buf[buf1_length + buf2_length];
	uint8_t *buf1 = &buf[buf2_length - 1];
	uint8_t *buf2 = buf;
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf1, buf1_length, buf2, buf2_length);
	CuAssertIntEquals (test, 1, status);
}

static void buffer_are_overlapping_test_same_buffer (CuTest *test)
{
	const size_t length = 32;
	uint8_t buf[length];
	int status;

	TEST_START;

	status = buffer_are_overlapping (buf, length, buf, length);
	CuAssertIntEquals (test, 1, status);
}

static void buffer_reverse_copy_test_empty_buffer (CuTest *test)
{
	const size_t length = 0;
	uint8_t buffer[1];
	uint8_t out[1];
	uint8_t forward[1];
	uint8_t reverse[1];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		forward[i] = i;
		reverse[j] = i;
	}

	buffer_reverse_copy (out, buffer, length);

	status = testing_validate_array (reverse, out, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_test_single_byte (CuTest *test)
{
	const size_t length = 1;
	uint8_t buffer[length];
	uint8_t out[length];
	uint8_t forward[length];
	uint8_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		forward[i] = i;
		reverse[j] = i;
	}

	buffer_reverse_copy (out, buffer, length);

	status = testing_validate_array (reverse, out, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_test_even_byte_count (CuTest *test)
{
	const size_t length = 16;
	uint8_t buffer[length];
	uint8_t out[length];
	uint8_t forward[length];
	uint8_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		forward[i] = i;
		reverse[j] = i;
	}

	buffer_reverse_copy (out, buffer, length);

	status = testing_validate_array (reverse, out, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_test_odd_byte_count (CuTest *test)
{
	const size_t length = 21;
	uint8_t buffer[length];
	uint8_t out[length];
	uint8_t forward[length];
	uint8_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		forward[i] = i;
		reverse[j] = i;
	}

	buffer_reverse_copy (out, buffer, length);

	status = testing_validate_array (reverse, out, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_test_null (CuTest *test)
{
	const size_t length = 10;
	uint8_t buffer[length];
	uint8_t out[length];
	uint8_t forward[length];
	uint8_t reverse[length];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < length; i++) {
		buffer[i] = i;
		forward[i] = i;
		reverse[i] = 0;
		out[i] = 0;
	}

	buffer_reverse_copy (NULL, buffer, length);

	status = testing_validate_array (reverse, out, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length);
	CuAssertIntEquals (test, 0, status);

	buffer_reverse_copy (out, NULL, length);

	status = testing_validate_array (reverse, out, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_dwords_test_empty_buffer (CuTest *test)
{
	const size_t length = 0;
	uint32_t buffer[1];
	uint32_t out[1];
	uint32_t forward[1];
	uint32_t reverse[1];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		forward[i] = i;
		reverse[j] = i;
	}

	status = buffer_reverse_copy_dwords (out, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (reverse, out, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_dwords_test_single_dowrd (CuTest *test)
{
	const size_t length = 1;
	uint32_t buffer[length];
	uint32_t out[length];
	uint32_t forward[length];
	uint32_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		forward[i] = i;
		reverse[j] = i;
	}

	status = buffer_reverse_copy_dwords (out, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (reverse, out, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_dwords_test_even_dword_count (CuTest *test)
{
	const size_t length = 16;
	uint32_t buffer[length];
	uint32_t out[length];
	uint32_t forward[length];
	uint32_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		forward[i] = i;
		reverse[j] = i;
	}

	status = buffer_reverse_copy_dwords (out, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (reverse, out, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_dwords_test_odd_dword_count (CuTest *test)
{
	const size_t length = 21;
	uint32_t buffer[length];
	uint32_t out[length];
	uint32_t forward[length];
	uint32_t reverse[length];
	size_t i;
	size_t j;
	int status;

	TEST_START;

	for (i = 0, j = (length - 1); i < length; i++, j--) {
		buffer[i] = i;
		forward[i] = i;
		reverse[j] = i;
	}

	status = buffer_reverse_copy_dwords (out, buffer, length);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (reverse, out, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_dwords_test_null (CuTest *test)
{
	const size_t length = 10;
	uint32_t buffer[length];
	uint32_t out[length];
	uint32_t forward[length];
	uint32_t reverse[length];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < length; i++) {
		buffer[i] = i;
		forward[i] = i;
		reverse[i] = 0;
		out[i] = 0;
	}

	status = buffer_reverse_copy_dwords (NULL, buffer, length);
	CuAssertIntEquals (test, BUFFER_UTIL_INVALID_ARGUMENT, status);

	status = testing_validate_array (reverse, out, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = buffer_reverse_copy_dwords (out, NULL, length);
	CuAssertIntEquals (test, BUFFER_UTIL_INVALID_ARGUMENT, status);

	status = testing_validate_array (reverse, out, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_reverse_copy_dwords_test_unaligned_buffer (CuTest *test)
{
	const size_t length = 16;
	uint32_t buffer[length];
	uint32_t out[length];
	uint32_t forward[length];
	uint32_t reverse[length];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < length; i++) {
		buffer[i] = i;
		forward[i] = i;
		reverse[i] = 0;
		out[i] = 0;
	}

	status = buffer_reverse_copy_dwords ((uint32_t*) (((uint8_t*) out) + 1), buffer, length);
	CuAssertIntEquals (test, BUFFER_UTIL_UNEXPETCED_ALIGNMENT, status);

	status = testing_validate_array (reverse, out, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = buffer_reverse_copy_dwords (out, (uint32_t*) (((uint8_t*) buffer) + 1), length);
	CuAssertIntEquals (test, BUFFER_UTIL_UNEXPETCED_ALIGNMENT, status);

	status = testing_validate_array (reverse, out, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (forward, buffer, length * sizeof (uint32_t));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_compare_test_match (CuTest *test)
{
	const size_t length = 14;
	uint8_t buf1[length];
	uint8_t buf2[length];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < length; i++) {
		buf1[i] = i;
		buf2[i] = i;
	}

	status = buffer_compare (buf1, buf2, length);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_compare_test_no_match (CuTest *test)
{
	const size_t length = 14;
	uint8_t buf1[length];
	uint8_t buf2[length];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < length; i++) {
		buf1[i] = i;
		buf2[i] = ~i;
	}

	status = buffer_compare (buf1, buf2, length);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_test_no_match_last_byte (CuTest *test)
{
	const size_t length = 14;
	uint8_t buf1[length];
	uint8_t buf2[length];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < length; i++) {
		buf1[i] = i;
		buf2[i] = i;
	}

	buf2[length - 1] ^= 0x55;

	status = buffer_compare (buf1, buf2, length);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_test_zero_length (CuTest *test)
{
	const size_t length = 14;
	uint8_t buf1[length];
	uint8_t buf2[length];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < length; i++) {
		buf1[i] = i;
		buf2[i] = i;
	}

	status = buffer_compare (buf1, buf2, 0);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_compare_test_match_both_null_zero_length (CuTest *test)
{
	int status;

	TEST_START;

	status = buffer_compare (NULL, NULL, 0);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_compare_test_match_both_null_non_zero_length (CuTest *test)
{
	int status;

	TEST_START;

	status = buffer_compare (NULL, NULL, 10);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_test_one_null_zero_length (CuTest *test)
{
	const size_t length = 32;
	uint8_t buf1[length];
	int status;

	TEST_START;

	status = buffer_compare (buf1, NULL, 0);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);

	status = buffer_compare (NULL, buf1, 0);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_test_one_null_non_zero_length (CuTest *test)
{
	const size_t length = 32;
	uint8_t buf1[length];
	int status;

	TEST_START;

	status = buffer_compare (buf1, NULL, length);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);

	status = buffer_compare (NULL, buf1, length);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_dwords_test_match (CuTest *test)
{
	const size_t dwords = 32;
	uint32_t buf1[dwords];
	uint32_t buf2[dwords];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < dwords; i++) {
		buf1[i] = i;
		buf2[i] = i;
	}

	status = buffer_compare_dwords (buf1, buf2, dwords);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_compare_dwords_test_no_match (CuTest *test)
{
	const size_t dwords = 32;
	uint32_t buf1[dwords];
	uint32_t buf2[dwords];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < dwords; i++) {
		buf1[i] = i;
		buf2[i] = ~i;
	}

	status = buffer_compare_dwords (buf1, buf2, dwords);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_dwords_test_no_match_last_dword (CuTest *test)
{
	const size_t dwords = 32;
	uint32_t buf1[dwords];
	uint32_t buf2[dwords];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < dwords; i++) {
		buf1[i] = i;
		buf2[i] = i;
	}

	buf2[dwords - 1] ^= 0x55;

	status = buffer_compare_dwords (buf1, buf2, dwords);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_dwords_test_zero_length (CuTest *test)
{
	const size_t dwords = 32;
	uint32_t buf1[dwords];
	uint32_t buf2[dwords];
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < dwords; i++) {
		buf1[i] = i;
		buf2[i] = i;
	}

	status = buffer_compare_dwords (buf1, buf2, 0);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_compare_dwords_test_match_both_null_zero_length (CuTest *test)
{
	int status;

	TEST_START;

	status = buffer_compare_dwords (NULL, NULL, 0);
	CuAssertIntEquals (test, 0, status);
}

static void buffer_compare_dwords_test_match_both_null_non_zero_length (CuTest *test)
{
	int status;

	TEST_START;

	status = buffer_compare_dwords (NULL, NULL, 10);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_dwords_test_one_null_zero_length (CuTest *test)
{
	const size_t dwords = 32;
	uint32_t buf1[dwords];
	int status;

	TEST_START;

	status = buffer_compare_dwords (buf1, NULL, 0);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);

	status = buffer_compare_dwords (NULL, buf1, 0);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_compare_dwords_test_one_null_non_zero_length (CuTest *test)
{
	const size_t dwords = 32;
	uint32_t buf1[dwords];
	int status;

	TEST_START;

	status = buffer_compare_dwords (buf1, NULL, dwords);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);

	status = buffer_compare_dwords (NULL, buf1, dwords);
	CuAssertIntEquals (test, BUFFER_UTIL_DATA_MISMATCH, status);
}

static void buffer_zerioze_test (CuTest *test)
{
	uint8_t buffer[32];
	uint8_t zero[32] = {0};
	size_t i;
	int status;

	TEST_START;

	for (i = 0; i < sizeof (buffer); i++) {
		buffer[i] = i;
	}

	buffer_zeroize (buffer, sizeof (buffer));

	status = testing_validate_array (buffer, zero, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_zerioze_test_zero_length (CuTest *test)
{
	uint8_t buffer[32];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (buffer); i++) {
		buffer[i] = i;
	}

	buffer_zeroize (buffer, 0);

	for (i = 0; i < sizeof (buffer); i++) {
		CuAssertIntEquals (test, i, buffer[i]);
	}
}

static void buffer_zerioze_test_null (CuTest *test)
{
	TEST_START;

	buffer_zeroize (NULL, 32);
}

static void buffer_zerioze_dwords_test (CuTest *test)
{
	uint32_t buffer[32];
	uint32_t zero[32] = {0};
	int status;

	TEST_START;

	memset (buffer, 0xff, sizeof (buffer));

	buffer_zeroize_dwords (buffer, ARRAY_SIZE (buffer));

	status = testing_validate_array (buffer, zero, sizeof (buffer));
	CuAssertIntEquals (test, 0, status);
}

static void buffer_zerioze_dwords_test_zero_length (CuTest *test)
{
	uint32_t buffer[32];
	size_t i;

	TEST_START;

	for (i = 0; i < ARRAY_SIZE (buffer); i++) {
		buffer[i] = i;
	}

	buffer_zeroize_dwords (buffer, 0);

	for (i = 0; i < ARRAY_SIZE (buffer); i++) {
		CuAssertIntEquals (test, i, buffer[i]);
	}
}

static void buffer_zerioze_dwords_test_null (CuTest *test)
{
	TEST_START;

	buffer_zeroize_dwords (NULL, 32);
}

static void buffer_unaligned_test_copy16_unaligned_src (CuTest *test)
{
	uint16_t value = 0;

	TEST_START;

	buffer_unaligned_copy16 (&value, (const uint16_t*) &BUFFER_TESTING_UNALIGNED_DATA[0]);
	CuAssertIntEquals (test, 0x0201, value);

	buffer_unaligned_copy16 (&value, (const uint16_t*) &BUFFER_TESTING_UNALIGNED_DATA[1]);
	CuAssertIntEquals (test, 0x0302, value);
}

static void buffer_unaligned_test_copy16_unaligned_dst (CuTest *test)
{
	uint8_t value[3] = {0, };

	TEST_START;

	buffer_unaligned_copy16 ((uint16_t*) &value[0],
		(const uint16_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[0]);
	CuAssertIntEquals (test, 0x02, value[1]);

	buffer_unaligned_copy16 ((uint16_t*) &value[1],
		(const uint16_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[1]);
	CuAssertIntEquals (test, 0x02, value[2]);
}

static void buffer_unaligned_test_copy24_unaligned_src (CuTest *test)
{
	uint32_t value = 0;

	TEST_START;

	buffer_unaligned_copy24 ((uint8_t*) &value, &BUFFER_TESTING_UNALIGNED_DATA[0]);
	CuAssertIntEquals (test, 0x030201, value);

	buffer_unaligned_copy24 ((uint8_t*) &value, &BUFFER_TESTING_UNALIGNED_DATA[1]);
	CuAssertIntEquals (test, 0x040302, value);
}

static void buffer_unaligned_test_copy24_unaligned_dst (CuTest *test)
{
	uint8_t value[4] = {0, };

	TEST_START;

	buffer_unaligned_copy24 (&value[0], BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[0]);
	CuAssertIntEquals (test, 0x02, value[1]);
	CuAssertIntEquals (test, 0x03, value[2]);

	buffer_unaligned_copy24 (&value[1], BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[1]);
	CuAssertIntEquals (test, 0x02, value[2]);
	CuAssertIntEquals (test, 0x03, value[3]);
}

static void buffer_unaligned_test_copy32_unaligned_src (CuTest *test)
{
	uint32_t value = 0;

	TEST_START;

	buffer_unaligned_copy32 (&value, (const uint32_t*) &BUFFER_TESTING_UNALIGNED_DATA[0]);
	CuAssertIntEquals (test, 0x04030201, value);

	buffer_unaligned_copy32 (&value, (const uint32_t*) &BUFFER_TESTING_UNALIGNED_DATA[1]);
	CuAssertIntEquals (test, 0x05040302, value);

	buffer_unaligned_copy32 (&value, (const uint32_t*) &BUFFER_TESTING_UNALIGNED_DATA[2]);
	CuAssertIntEquals (test, 0x06050403, value);

	buffer_unaligned_copy32 (&value, (const uint32_t*) &BUFFER_TESTING_UNALIGNED_DATA[3]);
	CuAssertIntEquals (test, 0x07060504, value);
}

static void buffer_unaligned_test_copy32_unaligned_dst (CuTest *test)
{
	uint8_t value[7] = {0, };

	TEST_START;

	buffer_unaligned_copy32 ((uint32_t*) &value[0],
		(const uint32_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[0]);
	CuAssertIntEquals (test, 0x02, value[1]);
	CuAssertIntEquals (test, 0x03, value[2]);
	CuAssertIntEquals (test, 0x04, value[3]);

	buffer_unaligned_copy32 ((uint32_t*) &value[1],
		(const uint32_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[1]);
	CuAssertIntEquals (test, 0x02, value[2]);
	CuAssertIntEquals (test, 0x03, value[3]);
	CuAssertIntEquals (test, 0x04, value[4]);

	buffer_unaligned_copy32 ((uint32_t*) &value[2],
		(const uint32_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[2]);
	CuAssertIntEquals (test, 0x02, value[3]);
	CuAssertIntEquals (test, 0x03, value[4]);
	CuAssertIntEquals (test, 0x04, value[5]);

	buffer_unaligned_copy32 ((uint32_t*) &value[3],
		(const uint32_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[3]);
	CuAssertIntEquals (test, 0x02, value[4]);
	CuAssertIntEquals (test, 0x03, value[5]);
	CuAssertIntEquals (test, 0x04, value[6]);
}

static void buffer_unaligned_test_copy64_unaligned_src (CuTest *test)
{
	uint64_t value = 0;

	TEST_START;

	buffer_unaligned_copy64 (&value, (const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[0]);
	CuAssertInt64Equals (test, 0x0807060504030201, value);

	buffer_unaligned_copy64 (&value, (const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[1]);
	CuAssertInt64Equals (test, 0x0908070605040302, value);

	buffer_unaligned_copy64 (&value, (const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[2]);
	CuAssertInt64Equals (test, 0x0a09080706050403, value);

	buffer_unaligned_copy64 (&value, (const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[3]);
	CuAssertInt64Equals (test, 0x0b0a090807060504, value);

	buffer_unaligned_copy64 (&value, (const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[4]);
	CuAssertInt64Equals (test, 0x0c0b0a0908070605, value);

	buffer_unaligned_copy64 (&value, (const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[5]);
	CuAssertInt64Equals (test, 0x0d0c0b0a09080706, value);

	buffer_unaligned_copy64 (&value, (const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[6]);
	CuAssertInt64Equals (test, 0x0e0d0c0b0a090807, value);

	buffer_unaligned_copy64 (&value, (const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[7]);
	CuAssertInt64Equals (test, 0x0f0e0d0c0b0a0908, value);
}

static void buffer_unaligned_test_copy64_unaligned_dst (CuTest *test)
{
	uint8_t value[15] = {0};

	TEST_START;

	buffer_unaligned_copy64 ((uint64_t*) &value[0],
		(const uint64_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[0]);
	CuAssertIntEquals (test, 0x02, value[1]);
	CuAssertIntEquals (test, 0x03, value[2]);
	CuAssertIntEquals (test, 0x04, value[3]);
	CuAssertIntEquals (test, 0x05, value[4]);
	CuAssertIntEquals (test, 0x06, value[5]);
	CuAssertIntEquals (test, 0x07, value[6]);
	CuAssertIntEquals (test, 0x08, value[7]);

	buffer_unaligned_copy64 ((uint64_t*) &value[1],
		(const uint64_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[1]);
	CuAssertIntEquals (test, 0x02, value[2]);
	CuAssertIntEquals (test, 0x03, value[3]);
	CuAssertIntEquals (test, 0x04, value[4]);
	CuAssertIntEquals (test, 0x05, value[5]);
	CuAssertIntEquals (test, 0x06, value[6]);
	CuAssertIntEquals (test, 0x07, value[7]);
	CuAssertIntEquals (test, 0x08, value[8]);

	buffer_unaligned_copy64 ((uint64_t*) &value[2],
		(const uint64_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[2]);
	CuAssertIntEquals (test, 0x02, value[3]);
	CuAssertIntEquals (test, 0x03, value[4]);
	CuAssertIntEquals (test, 0x04, value[5]);
	CuAssertIntEquals (test, 0x05, value[6]);
	CuAssertIntEquals (test, 0x06, value[7]);
	CuAssertIntEquals (test, 0x07, value[8]);
	CuAssertIntEquals (test, 0x08, value[9]);

	buffer_unaligned_copy64 ((uint64_t*) &value[3],
		(const uint64_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[3]);
	CuAssertIntEquals (test, 0x02, value[4]);
	CuAssertIntEquals (test, 0x03, value[5]);
	CuAssertIntEquals (test, 0x04, value[6]);
	CuAssertIntEquals (test, 0x05, value[7]);
	CuAssertIntEquals (test, 0x06, value[8]);
	CuAssertIntEquals (test, 0x07, value[9]);
	CuAssertIntEquals (test, 0x08, value[10]);

	buffer_unaligned_copy64 ((uint64_t*) &value[4],
		(const uint64_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[4]);
	CuAssertIntEquals (test, 0x02, value[5]);
	CuAssertIntEquals (test, 0x03, value[6]);
	CuAssertIntEquals (test, 0x04, value[7]);
	CuAssertIntEquals (test, 0x05, value[8]);
	CuAssertIntEquals (test, 0x06, value[9]);
	CuAssertIntEquals (test, 0x07, value[10]);
	CuAssertIntEquals (test, 0x08, value[11]);

	buffer_unaligned_copy64 ((uint64_t*) &value[5],
		(const uint64_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[5]);
	CuAssertIntEquals (test, 0x02, value[6]);
	CuAssertIntEquals (test, 0x03, value[7]);
	CuAssertIntEquals (test, 0x04, value[8]);
	CuAssertIntEquals (test, 0x05, value[9]);
	CuAssertIntEquals (test, 0x06, value[10]);
	CuAssertIntEquals (test, 0x07, value[11]);
	CuAssertIntEquals (test, 0x08, value[12]);

	buffer_unaligned_copy64 ((uint64_t*) &value[6],
		(const uint64_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[6]);
	CuAssertIntEquals (test, 0x02, value[7]);
	CuAssertIntEquals (test, 0x03, value[8]);
	CuAssertIntEquals (test, 0x04, value[9]);
	CuAssertIntEquals (test, 0x05, value[10]);
	CuAssertIntEquals (test, 0x06, value[11]);
	CuAssertIntEquals (test, 0x07, value[12]);
	CuAssertIntEquals (test, 0x08, value[13]);

	buffer_unaligned_copy64 ((uint64_t*) &value[7],
		(const uint64_t*) BUFFER_TESTING_UNALIGNED_DATA);
	CuAssertIntEquals (test, 0x01, value[7]);
	CuAssertIntEquals (test, 0x02, value[8]);
	CuAssertIntEquals (test, 0x03, value[9]);
	CuAssertIntEquals (test, 0x04, value[10]);
	CuAssertIntEquals (test, 0x05, value[11]);
	CuAssertIntEquals (test, 0x06, value[12]);
	CuAssertIntEquals (test, 0x07, value[13]);
	CuAssertIntEquals (test, 0x08, value[14]);
}

static void buffer_unaligned_test_read16 (CuTest *test)
{
	uint16_t value;

	TEST_START;

	value = buffer_unaligned_read16 ((const uint16_t*) &BUFFER_TESTING_UNALIGNED_DATA[0]);
	CuAssertIntEquals (test, 0x0201, value);

	value = buffer_unaligned_read16 ((const uint16_t*) &BUFFER_TESTING_UNALIGNED_DATA[1]);
	CuAssertIntEquals (test, 0x0302, value);
}

static void buffer_unaligned_test_read24 (CuTest *test)
{
	uint32_t value;

	TEST_START;

	value = buffer_unaligned_read24 (&BUFFER_TESTING_UNALIGNED_DATA[0]);
	CuAssertIntEquals (test, 0x030201, value);

	value = buffer_unaligned_read24 (&BUFFER_TESTING_UNALIGNED_DATA[1]);
	CuAssertIntEquals (test, 0x040302, value);
}

static void buffer_unaligned_test_read32 (CuTest *test)
{
	uint32_t value;

	TEST_START;

	value = buffer_unaligned_read32 ((const uint32_t*) &BUFFER_TESTING_UNALIGNED_DATA[0]);
	CuAssertIntEquals (test, 0x04030201, value);

	value = buffer_unaligned_read32 ((const uint32_t*) &BUFFER_TESTING_UNALIGNED_DATA[1]);
	CuAssertIntEquals (test, 0x05040302, value);

	value = buffer_unaligned_read32 ((const uint32_t*) &BUFFER_TESTING_UNALIGNED_DATA[2]);
	CuAssertIntEquals (test, 0x06050403, value);

	value = buffer_unaligned_read32 ((const uint32_t*) &BUFFER_TESTING_UNALIGNED_DATA[3]);
	CuAssertIntEquals (test, 0x07060504, value);
}

static void buffer_unaligned_test_read64 (CuTest *test)
{
	uint64_t value;

	TEST_START;

	value = buffer_unaligned_read64 ((const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[0]);
	CuAssertInt64Equals (test, 0x0807060504030201, value);

	value = buffer_unaligned_read64 ((const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[1]);
	CuAssertInt64Equals (test, 0x0908070605040302, value);

	value = buffer_unaligned_read64 ((const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[2]);
	CuAssertInt64Equals (test, 0x0a09080706050403, value);

	value = buffer_unaligned_read64 ((const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[3]);
	CuAssertInt64Equals (test, 0x0b0a090807060504, value);

	value = buffer_unaligned_read64 ((const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[4]);
	CuAssertInt64Equals (test, 0x0c0b0a0908070605, value);

	value = buffer_unaligned_read64 ((const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[5]);
	CuAssertInt64Equals (test, 0x0d0c0b0a09080706, value);

	value = buffer_unaligned_read64 ((const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[6]);
	CuAssertInt64Equals (test, 0x0e0d0c0b0a090807, value);

	value = buffer_unaligned_read64 ((const uint64_t*) &BUFFER_TESTING_UNALIGNED_DATA[7]);
	CuAssertInt64Equals (test, 0x0f0e0d0c0b0a0908, value);
}

static void buffer_unaligned_test_write16 (CuTest *test)
{
	uint8_t value[3] = {0, };

	TEST_START;

	buffer_unaligned_write16 ((uint16_t*) &value[0], 0x0201);
	CuAssertIntEquals (test, 0x01, value[0]);
	CuAssertIntEquals (test, 0x02, value[1]);

	buffer_unaligned_write16 ((uint16_t*) &value[1], 0x0201);
	CuAssertIntEquals (test, 0x01, value[1]);
	CuAssertIntEquals (test, 0x02, value[2]);
}

static void buffer_unaligned_test_write24 (CuTest *test)
{
	uint8_t value[4] = {0, };

	TEST_START;

	buffer_unaligned_write24 (&value[0], 0x030201);
	CuAssertIntEquals (test, 0x01, value[0]);
	CuAssertIntEquals (test, 0x02, value[1]);
	CuAssertIntEquals (test, 0x03, value[2]);

	buffer_unaligned_write24 (&value[1], 0x030201);
	CuAssertIntEquals (test, 0x01, value[1]);
	CuAssertIntEquals (test, 0x02, value[2]);
	CuAssertIntEquals (test, 0x03, value[3]);
}

static void buffer_unaligned_test_write32 (CuTest *test)
{
	uint8_t value[7] = {0, };

	TEST_START;

	buffer_unaligned_write32 ((uint32_t*) &value[0], 0x04030201);
	CuAssertIntEquals (test, 0x01, value[0]);
	CuAssertIntEquals (test, 0x02, value[1]);
	CuAssertIntEquals (test, 0x03, value[2]);
	CuAssertIntEquals (test, 0x04, value[3]);

	buffer_unaligned_write32 ((uint32_t*) &value[1], 0x04030201);
	CuAssertIntEquals (test, 0x01, value[1]);
	CuAssertIntEquals (test, 0x02, value[2]);
	CuAssertIntEquals (test, 0x03, value[3]);
	CuAssertIntEquals (test, 0x04, value[4]);

	buffer_unaligned_write32 ((uint32_t*) &value[2], 0x04030201);
	CuAssertIntEquals (test, 0x01, value[2]);
	CuAssertIntEquals (test, 0x02, value[3]);
	CuAssertIntEquals (test, 0x03, value[4]);
	CuAssertIntEquals (test, 0x04, value[5]);

	buffer_unaligned_write32 ((uint32_t*) &value[3], 0x04030201);
	CuAssertIntEquals (test, 0x01, value[3]);
	CuAssertIntEquals (test, 0x02, value[4]);
	CuAssertIntEquals (test, 0x03, value[5]);
	CuAssertIntEquals (test, 0x04, value[6]);
}

static void buffer_unaligned_test_write64 (CuTest *test)
{
	uint8_t value[15] = {0};

	TEST_START;

	buffer_unaligned_write64 ((uint64_t*) &value[0], 0x0807060504030201);
	CuAssertIntEquals (test, 0x01, value[0]);
	CuAssertIntEquals (test, 0x02, value[1]);
	CuAssertIntEquals (test, 0x03, value[2]);
	CuAssertIntEquals (test, 0x04, value[3]);
	CuAssertIntEquals (test, 0x05, value[4]);
	CuAssertIntEquals (test, 0x06, value[5]);
	CuAssertIntEquals (test, 0x07, value[6]);
	CuAssertIntEquals (test, 0x08, value[7]);

	buffer_unaligned_write64 ((uint64_t*) &value[1], 0x0807060504030201);
	CuAssertIntEquals (test, 0x01, value[1]);
	CuAssertIntEquals (test, 0x02, value[2]);
	CuAssertIntEquals (test, 0x03, value[3]);
	CuAssertIntEquals (test, 0x04, value[4]);
	CuAssertIntEquals (test, 0x05, value[5]);
	CuAssertIntEquals (test, 0x06, value[6]);
	CuAssertIntEquals (test, 0x07, value[7]);
	CuAssertIntEquals (test, 0x08, value[8]);

	buffer_unaligned_write64 ((uint64_t*) &value[2], 0x0807060504030201);
	CuAssertIntEquals (test, 0x01, value[2]);
	CuAssertIntEquals (test, 0x02, value[3]);
	CuAssertIntEquals (test, 0x03, value[4]);
	CuAssertIntEquals (test, 0x04, value[5]);
	CuAssertIntEquals (test, 0x05, value[6]);
	CuAssertIntEquals (test, 0x06, value[7]);
	CuAssertIntEquals (test, 0x07, value[8]);
	CuAssertIntEquals (test, 0x08, value[9]);

	buffer_unaligned_write64 ((uint64_t*) &value[3], 0x0807060504030201);
	CuAssertIntEquals (test, 0x01, value[3]);
	CuAssertIntEquals (test, 0x02, value[4]);
	CuAssertIntEquals (test, 0x03, value[5]);
	CuAssertIntEquals (test, 0x04, value[6]);
	CuAssertIntEquals (test, 0x05, value[7]);
	CuAssertIntEquals (test, 0x06, value[8]);
	CuAssertIntEquals (test, 0x07, value[9]);
	CuAssertIntEquals (test, 0x08, value[10]);

	buffer_unaligned_write64 ((uint64_t*) &value[4], 0x0807060504030201);
	CuAssertIntEquals (test, 0x01, value[4]);
	CuAssertIntEquals (test, 0x02, value[5]);
	CuAssertIntEquals (test, 0x03, value[6]);
	CuAssertIntEquals (test, 0x04, value[7]);
	CuAssertIntEquals (test, 0x05, value[8]);
	CuAssertIntEquals (test, 0x06, value[9]);
	CuAssertIntEquals (test, 0x07, value[10]);
	CuAssertIntEquals (test, 0x08, value[11]);

	buffer_unaligned_write64 ((uint64_t*) &value[5], 0x0807060504030201);
	CuAssertIntEquals (test, 0x01, value[5]);
	CuAssertIntEquals (test, 0x02, value[6]);
	CuAssertIntEquals (test, 0x03, value[7]);
	CuAssertIntEquals (test, 0x04, value[8]);
	CuAssertIntEquals (test, 0x05, value[9]);
	CuAssertIntEquals (test, 0x06, value[10]);
	CuAssertIntEquals (test, 0x07, value[11]);
	CuAssertIntEquals (test, 0x08, value[12]);

	buffer_unaligned_write64 ((uint64_t*) &value[6], 0x0807060504030201);
	CuAssertIntEquals (test, 0x01, value[6]);
	CuAssertIntEquals (test, 0x02, value[7]);
	CuAssertIntEquals (test, 0x03, value[8]);
	CuAssertIntEquals (test, 0x04, value[9]);
	CuAssertIntEquals (test, 0x05, value[10]);
	CuAssertIntEquals (test, 0x06, value[11]);
	CuAssertIntEquals (test, 0x07, value[12]);
	CuAssertIntEquals (test, 0x08, value[13]);

	buffer_unaligned_write64 ((uint64_t*) &value[7], 0x0807060504030201);
	CuAssertIntEquals (test, 0x01, value[7]);
	CuAssertIntEquals (test, 0x02, value[8]);
	CuAssertIntEquals (test, 0x03, value[9]);
	CuAssertIntEquals (test, 0x04, value[10]);
	CuAssertIntEquals (test, 0x05, value[11]);
	CuAssertIntEquals (test, 0x06, value[12]);
	CuAssertIntEquals (test, 0x07, value[13]);
	CuAssertIntEquals (test, 0x08, value[14]);
}


// *INDENT-OFF*
TEST_SUITE_START (buffer_util);

TEST (buffer_copy_test_full_buffer);
TEST (buffer_copy_test_full_buffer_null_offset);
TEST (buffer_copy_test_full_buffer_with_offset);
TEST (buffer_copy_test_full_buffer_with_offset_same_as_source_length);
TEST (buffer_copy_test_full_buffer_with_offset_longer_than_source);
TEST (buffer_copy_test_full_buffer_small_buffer);
TEST (buffer_copy_test_full_buffer_null_length);
TEST (buffer_copy_test_full_buffer_zero_length);
TEST (buffer_copy_test_full_buffer_with_offset_small_buffer);
TEST (buffer_copy_test_full_buffer_with_offset_small_buffer_past_source_end);
TEST (buffer_copy_test_null_source);
TEST (buffer_copy_test_zero_length_source);
TEST (buffer_copy_test_null_destination);
TEST (buffer_reverse_test_empty_buffer);
TEST (buffer_reverse_test_single_byte);
TEST (buffer_reverse_test_even_byte_count);
TEST (buffer_reverse_test_odd_byte_count);
TEST (buffer_reverse_test_null);
TEST (buffer_are_overlapping_test_no_overlap_buf1_first);
TEST (buffer_are_overlapping_test_no_overlap_buf2_first);
TEST (buffer_are_overlapping_test_buf2_ends_in_buf1);
TEST (buffer_are_overlapping_test_buf1_ends_in_buf2);
TEST (buffer_are_overlapping_test_same_start_byte);
TEST (buffer_are_overlapping_test_buf2_within_buf1);
TEST (buffer_are_overlapping_test_buf1_within_buf2);
TEST (buffer_are_overlapping_test_buf2_starts_in_buf1);
TEST (buffer_are_overlapping_test_buf1_starts_in_buf2);
TEST (buffer_are_overlapping_test_same_buffer);
TEST (buffer_reverse_copy_test_empty_buffer);
TEST (buffer_reverse_copy_test_single_byte);
TEST (buffer_reverse_copy_test_even_byte_count);
TEST (buffer_reverse_copy_test_odd_byte_count);
TEST (buffer_reverse_copy_test_null);
TEST (buffer_reverse_copy_dwords_test_empty_buffer);
TEST (buffer_reverse_copy_dwords_test_single_dowrd);
TEST (buffer_reverse_copy_dwords_test_even_dword_count);
TEST (buffer_reverse_copy_dwords_test_odd_dword_count);
TEST (buffer_reverse_copy_dwords_test_null);
TEST (buffer_reverse_copy_dwords_test_unaligned_buffer);
TEST (buffer_compare_test_match);
TEST (buffer_compare_test_no_match);
TEST (buffer_compare_test_no_match_last_byte);
TEST (buffer_compare_test_zero_length);
TEST (buffer_compare_test_match_both_null_zero_length);
TEST (buffer_compare_test_match_both_null_non_zero_length);
TEST (buffer_compare_test_one_null_zero_length);
TEST (buffer_compare_test_one_null_non_zero_length);
TEST (buffer_compare_dwords_test_match);
TEST (buffer_compare_dwords_test_no_match);
TEST (buffer_compare_dwords_test_no_match_last_dword);
TEST (buffer_compare_dwords_test_zero_length);
TEST (buffer_compare_dwords_test_match_both_null_zero_length);
TEST (buffer_compare_dwords_test_match_both_null_non_zero_length);
TEST (buffer_compare_dwords_test_one_null_zero_length);
TEST (buffer_compare_dwords_test_one_null_non_zero_length);
TEST (buffer_zerioze_test);
TEST (buffer_zerioze_test_zero_length);
TEST (buffer_zerioze_test_null);
TEST (buffer_zerioze_dwords_test);
TEST (buffer_zerioze_dwords_test_zero_length);
TEST (buffer_zerioze_dwords_test_null);
TEST (buffer_unaligned_test_copy16_unaligned_src);
TEST (buffer_unaligned_test_copy16_unaligned_dst);
TEST (buffer_unaligned_test_copy24_unaligned_src);
TEST (buffer_unaligned_test_copy24_unaligned_dst);
TEST (buffer_unaligned_test_copy32_unaligned_src);
TEST (buffer_unaligned_test_copy32_unaligned_dst);
TEST (buffer_unaligned_test_copy64_unaligned_src);
TEST (buffer_unaligned_test_copy64_unaligned_dst);
TEST (buffer_unaligned_test_read16);
TEST (buffer_unaligned_test_read24);
TEST (buffer_unaligned_test_read32);
TEST (buffer_unaligned_test_read64);
TEST (buffer_unaligned_test_write16);
TEST (buffer_unaligned_test_write24);
TEST (buffer_unaligned_test_write32);
TEST (buffer_unaligned_test_write64);

TEST_SUITE_END;
// *INDENT-ON*
