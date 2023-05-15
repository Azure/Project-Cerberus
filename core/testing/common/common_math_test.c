// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/common_math.h"


TEST_SUITE_LABEL ("common_math");


// Table with number of bits set for every value from 0-255
uint8_t num_bits[] = {
	0x0,0x1,0x1,0x2,0x1,0x2,0x2,0x3,0x1,0x2,0x2,0x3,0x2,0x3,0x3,0x4,0x1,0x2,0x2,0x3,0x2,0x3,0x3,0x4,
	0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,0x1,0x2,0x2,0x3,0x2,0x3,0x3,0x4,0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,
	0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,0x1,0x2,0x2,0x3,0x2,0x3,0x3,0x4,
	0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,
	0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,
	0x4,0x5,0x5,0x6,0x5,0x6,0x6,0x7,0x1,0x2,0x2,0x3,0x2,0x3,0x3,0x4,0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,
	0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,
	0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,0x4,0x5,0x5,0x6,0x5,0x6,0x6,0x7,
	0x2,0x3,0x3,0x4,0x3,0x4,0x4,0x5,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,
	0x4,0x5,0x5,0x6,0x5,0x6,0x6,0x7,0x3,0x4,0x4,0x5,0x4,0x5,0x5,0x6,0x4,0x5,0x5,0x6,0x5,0x6,0x6,0x7,
	0x4,0x5,0x5,0x6,0x5,0x6,0x6,0x7,0x5,0x6,0x6,0x7,0x6,0x7,0x7,0x8
};


/*******************
 * Test cases
 *******************/

static void common_math_test_get_num_bits_set (CuTest *test)
{
	int status;
	int i;

	TEST_START;

	for (i = 0; i < 256; ++i) {
		status = common_math_get_num_bits_set (i);
		CuAssertIntEquals (test, num_bits[i], status);
	}
}

static void common_math_test_get_num_bits_set_before_index (CuTest *test)
{
	int status;
	int i;

	TEST_START;

	for (i = 0; i < 8; ++i) {
		status = common_math_get_num_bits_set_before_index (0xff, i);
		CuAssertIntEquals (test, i, status);
	}
}

static void common_math_test_increment_byte_array (CuTest *test)
{
	int status;
	uint8_t len = 12;
	uint8_t input_array[12] = {0xff, 0xff, 0xff, 0xff, 0xfe, 0xab, 0, 0, 0, 0, 0, 0};
	uint8_t expected_array[12] = {0x0, 0x0, 0x0, 0x0, 0xff, 0xab, 0, 0, 0, 0, 0, 0};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_invalid_args (CuTest *test)
{
	int status;
	size_t len = 256;
	uint8_t input_array[256] = {0};

	TEST_START;

	status = common_math_increment_byte_array (input_array, 0, false);
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);

	status = common_math_increment_byte_array (NULL, len, false);
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_increment_byte_array_single_byte_zero_value (CuTest *test)
{
	int status;
	uint8_t len = 1;
	uint8_t input_array[1] = {0};
	uint8_t expected_array[1] = {1};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_single_byte_max_value_rolling_over (CuTest *test)
{
	int status;
	uint8_t len = 1;
	uint8_t input_array[1] = {0xff};
	uint8_t expected_array[1] = {0x0};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, true);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_single_byte_max_value_no_rolling_over (
	CuTest *test)
{
	int status;
	uint8_t len = 1;
	uint8_t input_array[1] = {0xff};
	uint8_t expected_array[1] = {0xff};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, COMMON_MATH_BOUNDARY_REACHED, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_byte_array_zero_value (CuTest *test)
{
	int status;
	uint8_t len = 12;
	uint8_t input_array[12] = {0};
	uint8_t expected_array[12] = {0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};;

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_byte_array_rolling_over_second_byte (
	CuTest *test)
{
	int status;
	uint8_t len = 12;
	uint8_t input_array[12] = {0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
	uint8_t expected_array[12] = {0, 0x1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_byte_array_rolling_over_later_byte (
	CuTest *test)
{
	int status;
	uint8_t len = 6;
	uint8_t input_array[6] = {0xff, 0xff, 0xff, 0, 0, 0};
	uint8_t expected_array[6] = {0, 0, 0, 0x1, 0, 0};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_byte_array_max_value_rolling_over (
	CuTest *test)
{
	int status;
	uint8_t len = 6;
	uint8_t input_array[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t expected_array[6] = {0};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, true);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_byte_array_max_value_no_rolling_over (
	CuTest *test)
{
	int status;
	uint8_t len = 6;
	uint8_t input_array[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	uint8_t expected_array[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, COMMON_MATH_BOUNDARY_REACHED, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_is_bit_set_in_array (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	int status;

	TEST_START;

	status = common_math_is_bit_set_in_array (bytes, sizeof (bytes), 0);
	CuAssertIntEquals (test, 1, status);

	status = common_math_is_bit_set_in_array (bytes, sizeof (bytes), 7);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_is_bit_set_in_array_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_is_bit_set_in_array (bytes, sizeof (bytes), 38);
	CuAssertIntEquals (test, 1, status);
}

static void common_math_test_is_bit_set_in_array_multiple_bytes_clear (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb};
	int status;

	TEST_START;

	status = common_math_is_bit_set_in_array (bytes, sizeof (bytes), 66);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_is_bit_set_in_array_null (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	int status;

	TEST_START;

	status = common_math_is_bit_set_in_array (NULL, sizeof (bytes), 0);
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_is_bit_set_in_array_out_of_range (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x40};
	int status;

	TEST_START;

	status = common_math_is_bit_set_in_array (bytes, sizeof (bytes), 40);
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);

	status = common_math_is_bit_set_in_array (bytes, 0, 0);
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);
}

static void common_math_test_set_bit_in_array (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	uint8_t expected[] = {0x75};
	int status;

	TEST_START;

	status = common_math_set_bit_in_array (bytes, sizeof (bytes), 5);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_bit_in_array_already_set (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	uint8_t expected[] = {0x55};
	int status;

	TEST_START;

	status = common_math_set_bit_in_array (bytes, sizeof (bytes), 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_bit_in_array_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00};
	uint8_t expected[] = {0x00, 0x00, 0x00, 0x02, 0x40, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_bit_in_array (bytes, sizeof (bytes), 25);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_bit_in_array_null (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	int status;

	TEST_START;

	status = common_math_set_bit_in_array (NULL, sizeof (bytes), 4);
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_set_bit_in_array_out_of_range (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x40};
	int status;

	TEST_START;

	status = common_math_set_bit_in_array (bytes, sizeof (bytes), 40);
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);

	status = common_math_set_bit_in_array (bytes, 0, 0);
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);
}

static void common_math_test_clear_bit_in_array (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	uint8_t expected[] = {0x51};
	int status;

	TEST_START;

	status = common_math_clear_bit_in_array (bytes, sizeof (bytes), 2);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_clear_bit_in_array_already_clear (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	uint8_t expected[] = {0x55};
	int status;

	TEST_START;

	status = common_math_clear_bit_in_array (bytes, sizeof (bytes), 5);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_clear_bit_in_array_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb};
	uint8_t expected[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xef, 0xff, 0xff, 0xfb};
	int status;

	TEST_START;

	status = common_math_clear_bit_in_array (bytes, sizeof (bytes), 44);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_clear_bit_in_array_null (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	int status;

	TEST_START;

	status = common_math_clear_bit_in_array (NULL, sizeof (bytes), 4);
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_clear_bit_in_array_out_of_range (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x40};
	int status;

	TEST_START;

	status = common_math_clear_bit_in_array (bytes, sizeof (bytes), 40);
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);

	status = common_math_clear_bit_in_array (bytes, 0, 0);
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);
}


TEST_SUITE_START (common_math);

TEST (common_math_test_get_num_bits_set);
TEST (common_math_test_get_num_bits_set_before_index);
TEST (common_math_test_increment_byte_array);
TEST (common_math_test_increment_byte_array_invalid_args);
TEST (common_math_test_increment_byte_array_single_byte_zero_value);
TEST (common_math_test_increment_byte_array_single_byte_max_value_rolling_over);
TEST (common_math_test_increment_byte_array_single_byte_max_value_no_rolling_over);
TEST (common_math_test_increment_byte_array_multiple_byte_array_zero_value);
TEST (common_math_test_increment_byte_array_multiple_byte_array_rolling_over_second_byte);
TEST (common_math_test_increment_byte_array_multiple_byte_array_rolling_over_later_byte);
TEST (common_math_test_increment_byte_array_multiple_byte_array_max_value_rolling_over);
TEST (common_math_test_increment_byte_array_multiple_byte_array_max_value_no_rolling_over);
TEST (common_math_test_is_bit_set_in_array);
TEST (common_math_test_is_bit_set_in_array_multiple_bytes);
TEST (common_math_test_is_bit_set_in_array_multiple_bytes_clear);
TEST (common_math_test_is_bit_set_in_array_null);
TEST (common_math_test_is_bit_set_in_array_out_of_range);
TEST (common_math_test_set_bit_in_array);
TEST (common_math_test_set_bit_in_array_already_set);
TEST (common_math_test_set_bit_in_array_multiple_bytes);
TEST (common_math_test_set_bit_in_array_null);
TEST (common_math_test_set_bit_in_array_out_of_range);
TEST (common_math_test_clear_bit_in_array);
TEST (common_math_test_clear_bit_in_array_already_clear);
TEST (common_math_test_clear_bit_in_array_multiple_bytes);
TEST (common_math_test_clear_bit_in_array_null);
TEST (common_math_test_clear_bit_in_array_out_of_range);

TEST_SUITE_END;
