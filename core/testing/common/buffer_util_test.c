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

TEST_SUITE_END;
