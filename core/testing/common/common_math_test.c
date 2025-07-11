// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "testing.h"
#include "common/common_math.h"


TEST_SUITE_LABEL ("common_math");


/**
 * Table with number of bits set for every value from 0-255
 */
uint8_t num_bits[] = {
	0x0, 0x1, 0x1, 0x2, 0x1, 0x2, 0x2, 0x3, 0x1, 0x2, 0x2, 0x3, 0x2, 0x3, 0x3, 0x4,
	0x1, 0x2, 0x2, 0x3, 0x2, 0x3, 0x3, 0x4, 0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5,
	0x1, 0x2, 0x2, 0x3, 0x2, 0x3, 0x3, 0x4, 0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5,
	0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5, 0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6,
	0x1, 0x2, 0x2, 0x3, 0x2, 0x3, 0x3, 0x4, 0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5,
	0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5, 0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6,
	0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5, 0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6,
	0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6, 0x4, 0x5, 0x5, 0x6, 0x5, 0x6, 0x6, 0x7,
	0x1, 0x2, 0x2, 0x3, 0x2, 0x3, 0x3, 0x4, 0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5,
	0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5, 0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6,
	0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5, 0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6,
	0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6, 0x4, 0x5, 0x5, 0x6, 0x5, 0x6, 0x6, 0x7,
	0x2, 0x3, 0x3, 0x4, 0x3, 0x4, 0x4, 0x5, 0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6,
	0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6, 0x4, 0x5, 0x5, 0x6, 0x5, 0x6, 0x6, 0x7,
	0x3, 0x4, 0x4, 0x5, 0x4, 0x5, 0x5, 0x6, 0x4, 0x5, 0x5, 0x6, 0x5, 0x6, 0x6, 0x7,
	0x4, 0x5, 0x5, 0x6, 0x5, 0x6, 0x6, 0x7, 0x5, 0x6, 0x6, 0x7, 0x6, 0x7, 0x7, 0x8
};

/**
 * Table with number of contiguous bits set for every value from 0-255
 */
uint8_t num_contiguous_bits[] = {
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x4,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x5,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x4,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x6,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x4,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x5,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x4,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x7,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x4,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x5,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x4,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x6,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x4,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x5,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x4,
	0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x3, 0x0, 0x1, 0x0, 0x2, 0x0, 0x1, 0x0, 0x8
};


/*******************
 * Test cases
 *******************/

static void common_math_test_saturing_increment_u8 (CuTest *test)
{
	TEST_START;

	CuAssertIntEquals (test, 1, common_math_saturating_increment_u8 (0));
	CuAssertIntEquals (test, (UINT8_MAX / 2 + 1),
		common_math_saturating_increment_u8 (UINT8_MAX / 2));
	CuAssertIntEquals (test, UINT8_MAX, common_math_saturating_increment_u8 (UINT8_MAX - 1));
	CuAssertIntEquals (test, UINT8_MAX, common_math_saturating_increment_u8 (UINT8_MAX));
}

static void common_math_test_saturing_increment_u16 (CuTest *test)
{
	TEST_START;

	CuAssertIntEquals (test, 1, common_math_saturating_increment_u16 (0));
	CuAssertIntEquals (test, (UINT16_MAX / 2 + 1),
		common_math_saturating_increment_u16 (UINT16_MAX / 2));
	CuAssertIntEquals (test, UINT16_MAX, common_math_saturating_increment_u16 (UINT16_MAX - 1));
	CuAssertIntEquals (test, UINT16_MAX, common_math_saturating_increment_u16 (UINT16_MAX));
}

static void common_math_test_saturing_increment_u32 (CuTest *test)
{
	TEST_START;

	CuAssertIntEquals (test, 1, common_math_saturating_increment_u32 (0));
	CuAssertIntEquals (test, (UINT32_MAX / 2 + 1),
		common_math_saturating_increment_u32 (UINT32_MAX / 2));
	CuAssertIntEquals (test, UINT32_MAX, common_math_saturating_increment_u32 (UINT32_MAX - 1));
	CuAssertIntEquals (test, UINT32_MAX, common_math_saturating_increment_u32 (UINT32_MAX));
}

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

static void common_math_test_get_num_bits_set_before_index_out_of_range (CuTest *test)
{
	int status;

	TEST_START;

	status = common_math_get_num_bits_set_before_index (0x5a, 9);
	CuAssertIntEquals (test, 4, status);
}

static void common_math_test_increment_byte_array_single_byte_zero_value (CuTest *test)
{
	int status;
	uint8_t len = 1;
	uint8_t input_array[1] = {0x00};
	uint8_t expected_array[1] = {0x01};

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
	uint8_t expected_array[1] = {0x00};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, true);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_bytes (CuTest *test)
{
	int status;
	uint8_t len = 12;
	uint8_t input_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45
	};
	uint8_t expected_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x46
	};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_bytes_rolling_over_first_byte (
	CuTest *test)
{
	int status;
	uint8_t len = 12;
	uint8_t input_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff
	};
	uint8_t expected_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00
	};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_bytes_rolling_over_later_byte (
	CuTest *test)
{
	int status;
	uint8_t len = 6;
	uint8_t input_array[6] = {0x00, 0x00, 0x00, 0xff, 0xff, 0xff};
	uint8_t expected_array[6] = {0x00, 0x00, 0x01, 0x00, 0x00, 0x00};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_bytes_non_zero_after_rollover_byte (
	CuTest *test)
{
	int status;
	uint8_t len = 12;
	uint8_t input_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xfe, 0xff, 0xff, 0xff, 0xff
	};
	uint8_t expected_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xab, 0xff, 0x00, 0x00, 0x00, 0x00
	};

	TEST_START;

	status = common_math_increment_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_increment_byte_array_multiple_bytes_max_value_rolling_over (
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

static void common_math_test_increment_byte_array_multiple_bytes_max_value_no_rolling_over (
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

static void common_math_test_decrement_byte_array_single_byte (CuTest *test)
{
	int status;
	uint8_t len = 1;
	uint8_t input_array[1] = {0x39};
	uint8_t expected_array[1] = {0x38};

	TEST_START;

	status = common_math_decrement_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_decrement_byte_array_single_byte_zero_rolling_over (CuTest *test)
{
	int status;
	uint8_t len = 1;
	uint8_t input_array[1] = {0x00};
	uint8_t expected_array[1] = {0xff};

	TEST_START;

	status = common_math_decrement_byte_array (input_array, len, true);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_decrement_byte_array_multiple_bytes (CuTest *test)
{
	int status;
	uint8_t len = 12;
	uint8_t input_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc
	};
	uint8_t expected_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbb
	};

	TEST_START;

	status = common_math_decrement_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_decrement_byte_array_multiple_bytes_rolling_over_first_byte (
	CuTest *test)
{
	int status;
	uint8_t len = 12;
	uint8_t input_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x33, 0x00
	};
	uint8_t expected_array[12] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x32, 0xff
	};

	TEST_START;

	status = common_math_decrement_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_decrement_byte_array_multiple_bytes_rolling_over_later_byte (
	CuTest *test)
{
	int status;
	uint8_t len = 6;
	uint8_t input_array[6] = {0x00, 0x00, 0x68, 0x00, 0x00, 0x00};
	uint8_t expected_array[6] = {0x00, 0x00, 0x67, 0xff, 0xff, 0xff};

	TEST_START;

	status = common_math_decrement_byte_array (input_array, len, false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_decrement_byte_array_multiple_bytes_zero_rolling_over (CuTest *test)
{
	int status;
	uint8_t len = 6;
	uint8_t input_array[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	uint8_t expected_array[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

	TEST_START;

	status = common_math_decrement_byte_array (input_array, len, true);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_decrement_byte_array_null (CuTest *test)
{
	int status;
	size_t len = 256;
	uint8_t input_array[256] = {0};

	TEST_START;

	status = common_math_decrement_byte_array (NULL, len, false);
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);

	status = common_math_decrement_byte_array (input_array, 0, false);
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_decrement_byte_array_single_byte_zero_no_rolling_over (CuTest *test)
{
	int status;
	uint8_t len = 1;
	uint8_t input_array[1] = {0x00};
	uint8_t expected_array[1] = {0x00};

	TEST_START;

	status = common_math_decrement_byte_array (input_array, len, false);
	CuAssertIntEquals (test, COMMON_MATH_BOUNDARY_REACHED, status);

	status = testing_validate_array (expected_array, input_array, len);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_decrement_byte_array_multiple_bytes_zero_no_rolling_over (CuTest *test)
{
	int status;
	uint8_t len = 6;
	uint8_t input_array[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	uint8_t expected_array[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	TEST_START;

	status = common_math_decrement_byte_array (input_array, len, false);
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

static void common_math_test_get_num_bits_set_in_array_single_byte (CuTest *test)
{
	int status;
	int i;

	TEST_START;

	for (i = 0; i < 256; ++i) {
		uint8_t byte = i;

		status = common_math_get_num_bits_set_in_array (&byte, 1);
		CuAssertIntEquals (test, num_bits[i], status);
	}
}

static void common_math_test_get_num_bits_set_in_array_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0x03, 0x30, 0x55, 0xff};
	int status;

	TEST_START;

	status = common_math_get_num_bits_set_in_array (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 16, status);
}

static void common_math_test_get_num_bits_set_in_array_zero_bytes (CuTest *test)
{
	uint8_t bytes[] = {0x03, 0x30, 0x55, 0xff};
	int status;

	TEST_START;

	status = common_math_get_num_bits_set_in_array (bytes, 0);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_get_num_bits_set_in_array_null (CuTest *test)
{
	uint8_t bytes[] = {0x03, 0x30, 0x55, 0xff};
	int status;

	TEST_START;

	status = common_math_get_num_bits_set_in_array (NULL, sizeof (bytes));
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_get_num_contiguous_bits_set (CuTest *test)
{
	int status;
	int i;

	TEST_START;

	for (i = 0; i < 256; ++i) {
		status = common_math_get_num_contiguous_bits_set (i);
		CuAssertIntEquals (test, num_contiguous_bits[i], status);
	}
}

static void common_math_test_get_num_contiguous_bits_set_in_array_single_byte (CuTest *test)
{
	int status;
	int i;

	TEST_START;

	for (i = 0; i < 256; ++i) {
		uint8_t byte = i;

		status = common_math_get_num_contiguous_bits_set_in_array (&byte, 1);
		CuAssertIntEquals (test, num_contiguous_bits[i], status);
	}
}

static void common_math_test_get_num_contiguous_bits_set_in_array_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0x55, 0xff};
	int status;

	TEST_START;

	status = common_math_get_num_contiguous_bits_set_in_array (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 17, status);
}

static void common_math_test_get_num_contiguous_bits_set_in_array_zero_bytes (CuTest *test)
{
	uint8_t bytes[] = {0x03, 0x30, 0x55, 0xff};
	int status;

	TEST_START;

	status = common_math_get_num_contiguous_bits_set_in_array (bytes, 0);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_get_num_contiguous_bits_set_in_array_null (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0x55, 0xff};
	int status;

	TEST_START;

	status = common_math_get_num_contiguous_bits_set_in_array (NULL, sizeof (bytes));
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_set_next_bit_in_array (CuTest *test)
{
	uint8_t bytes[] = {0x03};
	uint8_t expected[] = {0x07};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_first_bit (CuTest *test)
{
	uint8_t bytes[] = {0x00};
	uint8_t expected[] = {0x01};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0x1f, 0x00, 0x00, 0x00};
	uint8_t expected[] = {0xff, 0xff, 0x3f, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_multiple_bytes_first_bit (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00};
	uint8_t expected[] = {0x01, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_null (CuTest *test)
{
	uint8_t bytes[] = {0x03};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array (NULL, sizeof (bytes));
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_set_next_bit_in_array_zero_bytes (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0x1f, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array (bytes, 0);
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);
}

static void common_math_test_set_next_bit_in_array_all_bits_sit (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array (bytes, sizeof (bytes));
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);
}

static void common_math_test_set_next_bit_in_array_even_count (CuTest *test)
{
	uint8_t bytes[] = {0x07};
	uint8_t expected[] = {0x0f};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_even_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_even_count_no_bits_set (CuTest *test)
{
	uint8_t bytes[] = {0x00};
	uint8_t expected[] = {0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_even_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_even_count_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0x1f, 0x00, 0x00, 0x00};
	uint8_t expected[] = {0xff, 0xff, 0x3f, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_even_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_even_count_multiple_bytes_no_bits_set (
	CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00};
	uint8_t expected[] = {0x00, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_even_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_even_count_set_multiple_bits (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0xff, 0x55, 0x05, 0x00};
	uint8_t expected[] = {0xff, 0xff, 0xff, 0xff, 0x0f, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_even_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_even_count_zero_bytes (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0x1f, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	/* A zero-length array has an even number of bits set. */
	status = common_math_set_next_bit_in_array_even_count (bytes, 0);
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_even_count_all_bits_set (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_even_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_even_count_null (CuTest *test)
{
	uint8_t bytes[] = {0x03};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_even_count (NULL, sizeof (bytes));
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_set_next_bit_in_array_odd_count (CuTest *test)
{
	uint8_t bytes[] = {0x03};
	uint8_t expected[] = {0x07};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_odd_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_odd_count_no_bits_set (CuTest *test)
{
	uint8_t bytes[] = {0x01};
	uint8_t expected[] = {0x01};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_odd_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_odd_count_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0x0f, 0x00, 0x00, 0x00};
	uint8_t expected[] = {0xff, 0xff, 0x1f, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_odd_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_odd_count_multiple_bytes_no_bits_set (
	CuTest *test)
{
	uint8_t bytes[] = {0x01, 0x00, 0x00};
	uint8_t expected[] = {0x01, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_odd_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_odd_count_set_multiple_bits (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0xff, 0xaa, 0x0a, 0x00};
	uint8_t expected[] = {0xff, 0xff, 0xff, 0xff, 0x1f, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_odd_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (expected, bytes, sizeof (expected));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_set_next_bit_in_array_odd_count_null (CuTest *test)
{
	uint8_t bytes[] = {0x03};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_odd_count (NULL, sizeof (bytes));
	CuAssertIntEquals (test, COMMON_MATH_INVALID_ARGUMENT, status);
}

static void common_math_test_set_next_bit_in_array_odd_count_zero_bytes (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0x1f, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_odd_count (bytes, 0);
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);
}

static void common_math_test_set_next_bit_in_array_odd_count_all_bits_set (CuTest *test)
{
	uint8_t bytes[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int status;

	TEST_START;

	status = common_math_set_next_bit_in_array_odd_count (bytes, sizeof (bytes));
	CuAssertIntEquals (test, COMMON_MATH_OUT_OF_RANGE, status);
}

static void common_math_test_is_array_zero (CuTest *test)
{
	uint8_t zero[] = {0x00};
	uint8_t non_zero[] = {0x55};
	int status;

	TEST_START;

	status = common_math_is_array_zero (zero, sizeof (zero));
	CuAssertIntEquals (test, true, status);

	status = common_math_is_array_zero (non_zero, sizeof (non_zero));
	CuAssertIntEquals (test, false, status);
}

static void common_math_test_is_array_zero_multiple_bytes (CuTest *test)
{
	uint8_t zero[] = {0x00, 0x00, 0x00, 0x00};
	uint8_t non_zero[] = {0x00, 0x00, 0x55, 0x00};
	int status;

	TEST_START;

	status = common_math_is_array_zero (zero, sizeof (zero));
	CuAssertIntEquals (test, true, status);

	status = common_math_is_array_zero (non_zero, sizeof (non_zero));
	CuAssertIntEquals (test, false, status);
}

static void common_math_test_is_array_zero_multiple_words (CuTest *test)
{
	uint8_t zero[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	uint8_t non_zero[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00
	};
	int status;

	TEST_START;

	status = common_math_is_array_zero (zero, sizeof (zero));
	CuAssertIntEquals (test, true, status);

	status = common_math_is_array_zero (non_zero, sizeof (non_zero));
	CuAssertIntEquals (test, false, status);
}

static void common_math_test_is_array_zero_multiple_bytes_end_not_aligned (CuTest *test)
{
	uint8_t zero[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	uint8_t non_zero[] = {0x00, 0x00, 0x00, 0x00, 0x55, 0x00};
	int status;

	TEST_START;

	status = common_math_is_array_zero (zero, sizeof (zero));
	CuAssertIntEquals (test, true, status);

	status = common_math_is_array_zero (non_zero, sizeof (non_zero));
	CuAssertIntEquals (test, false, status);
}

static void common_math_test_is_array_zero_multiple_words_start_not_aligned (CuTest *test)
{
	uint8_t zero[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00
	};
	uint8_t non_zero[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0x00
	};
	int status;

	TEST_START;

	status = common_math_is_array_zero (&zero[1], sizeof (zero) - 1);
	CuAssertIntEquals (test, true, status);

	status = common_math_is_array_zero (&non_zero[3], sizeof (non_zero) - 3);
	CuAssertIntEquals (test, false, status);
}

static void common_math_test_is_array_zero_null (CuTest *test)
{
	int status;

	TEST_START;

	status = common_math_is_array_zero (NULL, 1);
	CuAssertIntEquals (test, false, status);
}

static void common_math_test_is_array_zero_empty (CuTest *test)
{
	uint8_t zero[] = {0x00};
	int status;

	TEST_START;

	status = common_math_is_array_zero (zero, 0);
	CuAssertIntEquals (test, false, status);
}

static void common_math_test_right_shift_array_single_byte (CuTest *test)
{
	uint8_t data[] = {0x55};
	uint8_t expected[] = {0x2a};
	int status;

	TEST_START;

	common_math_right_shift_array (data, sizeof (data), 1);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_right_shift_array_multiple_shift_less_than_one_byte (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34};
	uint8_t expected[] = {0x05, 0x5a, 0xa1, 0x23};
	int status;

	TEST_START;

	common_math_right_shift_array (data, sizeof (data), 4);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_right_shift_array_multiple_shift_more_than_one_byte (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34, 0x56, 0x78};
	uint8_t expected[] = {0x00, 0x00, 0x01, 0x56, 0xa8, 0x48};
	int status;

	TEST_START;

	common_math_right_shift_array (data, sizeof (data), 22);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_right_shift_array_full_bytes (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34, 0x56, 0x78};
	uint8_t expected[] = {0x00, 0x00, 0x00, 0x00, 0x55, 0xaa};
	int status;

	TEST_START;

	common_math_right_shift_array (data, sizeof (data), 32);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_right_shift_array_more_than_length (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34};
	uint8_t expected[] = {0x00, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	common_math_right_shift_array (data, sizeof (data), 33);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_right_shift_array_full_array (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34, 0x56, 0x78};
	uint8_t expected[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	common_math_right_shift_array (data, sizeof (data), 48);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_right_shift_leave_one_bit (CuTest *test)
{
	uint8_t data[] = {0xaa, 0x55, 0x12, 0x34, 0x56, 0x78};
	uint8_t expected[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
	int status;

	TEST_START;

	common_math_right_shift_array (data, sizeof (data), 47);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_right_shift_array_null (CuTest *test)
{
	uint8_t data[] = {0x55};
	uint8_t expected[] = {0x55};
	int status;

	TEST_START;

	common_math_right_shift_array (NULL, sizeof (data), 3);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_right_shift_array_empty (CuTest *test)
{
	uint8_t data[] = {0x55};
	uint8_t expected[] = {0x55};
	int status;

	TEST_START;

	common_math_right_shift_array (data, 0, 3);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}


static void common_math_test_right_shift_array_no_shift (CuTest *test)
{
	uint8_t data[] = {0x55};
	uint8_t expected[] = {0x55};
	int status;

	TEST_START;

	common_math_right_shift_array (data, sizeof (data), 0);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_array_single_byte (CuTest *test)
{
	uint8_t data[] = {0x55};
	uint8_t expected[] = {0xaa};
	int status;

	TEST_START;

	common_math_left_shift_array (data, sizeof (data), 1);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_array_multiple_shift_less_than_one_byte (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34};
	uint8_t expected[] = {0x5a, 0xa1, 0x23, 0x40};
	int status;

	TEST_START;

	common_math_left_shift_array (data, sizeof (data), 4);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_array_multiple_shift_more_than_one_byte (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x87, 0x65, 0x43, 0x21};
	uint8_t expected[] = {0xd9, 0x50, 0xc8, 0x40, 0x00, 0x00};
	int status;

	TEST_START;

	common_math_left_shift_array (data, sizeof (data), 22);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_array_full_bytes (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34, 0x56, 0x78};
	uint8_t expected[] = {0x56, 0x78, 0x00, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	common_math_left_shift_array (data, sizeof (data), 32);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_array_more_than_length (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34};
	uint8_t expected[] = {0x00, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	common_math_left_shift_array (data, sizeof (data), 33);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_array_full_array (CuTest *test)
{
	uint8_t data[] = {0x55, 0xaa, 0x12, 0x34, 0x56, 0x78};
	uint8_t expected[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	common_math_left_shift_array (data, sizeof (data), 48);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_leave_one_bit (CuTest *test)
{
	uint8_t data[] = {0xaa, 0x55, 0x12, 0x34, 0x56, 0x79};
	uint8_t expected[] = {0x80, 0x00, 0x00, 0x00, 0x00, 0x00};
	int status;

	TEST_START;

	common_math_left_shift_array (data, sizeof (data), 47);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_array_null (CuTest *test)
{
	uint8_t data[] = {0x55};
	uint8_t expected[] = {0x55};
	int status;

	TEST_START;

	common_math_left_shift_array (NULL, sizeof (data), 3);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_left_shift_array_empty (CuTest *test)
{
	uint8_t data[] = {0x55};
	uint8_t expected[] = {0x55};
	int status;

	TEST_START;

	common_math_left_shift_array (data, 0, 3);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}


static void common_math_test_left_shift_array_no_shift (CuTest *test)
{
	uint8_t data[] = {0x55};
	uint8_t expected[] = {0x55};
	int status;

	TEST_START;

	common_math_left_shift_array (data, sizeof (data), 0);

	status = testing_validate_array (expected, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_swap_bytes_uint16 (CuTest *test)
{
	uint16_t org = 0x1234;
	uint16_t swap = 0x3412;

	TEST_START;

	CuAssertIntEquals (test, swap, common_math_swap_bytes_uint16 (org));
}

static void common_math_test_swap_bytes_uint32 (CuTest *test)
{
	uint32_t org = 0x12345678;
	uint32_t swap = 0x78563412;

	TEST_START;

	CuAssertIntEquals (test, swap, common_math_swap_bytes_uint32 (org));
}

static void common_math_test_swap_bytes_uint64 (CuTest *test)
{
	uint64_t org = 0x123456789abcdef0;
	uint64_t swap = 0xf0debc9a78563412;

	TEST_START;

	CuAssertInt64Equals (test, swap, common_math_swap_bytes_uint64 (org));
}

static void common_math_test_compare_array (CuTest *test)
{
	uint8_t bytes[] = {0x55};
	uint8_t match[] = {0x55};
	uint8_t larger[] = {0x56};
	uint8_t smaller[] = {0x54};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), match, sizeof (match));
	CuAssertIntEquals (test, 0, status);

	status = common_math_compare_array (bytes, sizeof (bytes), larger, sizeof (larger));
	CuAssertTrue (test, (status < 0));

	status = common_math_compare_array (bytes, sizeof (bytes), smaller, sizeof (smaller));
	CuAssertTrue (test, (status > 0));
}

static void common_math_test_compare_array_multiple_bytes (CuTest *test)
{
	uint8_t bytes[] = {0x12, 0x34, 0x56, 0x78};
	uint8_t match[] = {0x12, 0x34, 0x56, 0x78};
	uint8_t larger[] = {0x12, 0x43, 0x56, 0x78};
	uint8_t smaller[] = {0x12, 0x34, 0x56, 0x67};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), match, sizeof (match));
	CuAssertIntEquals (test, 0, status);

	status = common_math_compare_array (bytes, sizeof (bytes), larger, sizeof (larger));
	CuAssertTrue (test, (status < 0));

	status = common_math_compare_array (bytes, sizeof (bytes), smaller, sizeof (smaller));
	CuAssertTrue (test, (status > 0));
}

static void common_math_test_compare_array_zero_padded_reference (CuTest *test)
{
	uint8_t bytes[] = {0x12, 0x34, 0x56, 0x78};
	uint8_t match[] = {0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78};
	uint8_t larger[] = {0x00, 0x12, 0x43, 0x56, 0x78};
	uint8_t smaller[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x67};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), match, sizeof (match));
	CuAssertIntEquals (test, 0, status);

	status = common_math_compare_array (bytes, sizeof (bytes), larger, sizeof (larger));
	CuAssertTrue (test, (status < 0));

	status = common_math_compare_array (bytes, sizeof (bytes), smaller, sizeof (smaller));
	CuAssertTrue (test, (status > 0));
}

static void common_math_test_compare_array_zero_padded_comparison (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
	uint8_t match[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
	uint8_t larger[] = {0x12, 0x43, 0x56, 0x78, 0x9a, 0xbc};
	uint8_t smaller[] = {0x12, 0x34, 0x56, 0x78, 0x99, 0xbc};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), match, sizeof (match));
	CuAssertIntEquals (test, 0, status);

	status = common_math_compare_array (bytes, sizeof (bytes), larger, sizeof (larger));
	CuAssertTrue (test, (status < 0));

	status = common_math_compare_array (bytes, sizeof (bytes), smaller, sizeof (smaller));
	CuAssertTrue (test, (status > 0));
}

static void common_math_test_compare_array_both_zero_padded (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a};
	uint8_t match[] = {0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a};
	uint8_t match2[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), match, sizeof (match));
	CuAssertIntEquals (test, 0, status);

	status = common_math_compare_array (bytes, sizeof (bytes), match2, sizeof (match2));
	CuAssertIntEquals (test, 0, status);
}

static void common_math_test_compare_array_shorter_than_reference (CuTest *test)
{
	uint8_t bytes[] = {0x12, 0x34, 0x56, 0x78};
	uint8_t compare[] = {0x12, 0x34, 0x56, 0x78};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes) - 1, compare, sizeof (compare));
	CuAssertTrue (test, (status < 0));
}

static void common_math_test_compare_array_shorter_than_reference_after_zero_padding (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78};
	uint8_t match[] = {0x12, 0x34, 0x56, 0x78, 0x9a};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), match, sizeof (match));
	CuAssertTrue (test, (status < 0));
}

static void common_math_test_compare_array_shorter_than_reference_with_zero_padding (CuTest *test)
{
	uint8_t bytes[] = {0x12, 0x34};
	uint8_t compare[] = {0x00, 0x12, 0x34, 0x56};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), compare, sizeof (compare));
	CuAssertTrue (test, (status < 0));
}

static void common_math_test_compare_array_longer_than_reference (CuTest *test)
{
	uint8_t bytes[] = {0x12, 0x34, 0x56, 0x78};
	uint8_t compare[] = {0x12, 0x34, 0x56, 0x78};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), compare, sizeof (compare) - 1);
	CuAssertTrue (test, (status > 0));
}

static void common_math_test_compare_array_longer_than_reference_after_zero_padding (CuTest *test)
{
	uint8_t bytes[] = {0x12, 0x34, 0x56, 0x78};
	uint8_t compare[] = {0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), compare, sizeof (compare) - 1);
	CuAssertTrue (test, (status > 0));
}

static void common_math_test_compare_array_longer_than_reference_with_zero_padding (CuTest *test)
{
	uint8_t bytes[] = {0x00, 0x00, 0x11, 0x12, 0x34, 0x56, 0x78};
	uint8_t compare[] = {0x12, 0x34, 0x56, 0x78};
	int status;

	TEST_START;

	status = common_math_compare_array (bytes, sizeof (bytes), compare, sizeof (compare) - 1);
	CuAssertTrue (test, (status > 0));
}

static void common_math_test_compare_array_empty_array (CuTest *test)
{
	uint8_t bytes[] = {0x12, 0x34, 0x56, 0x78};
	uint8_t compare[] = {0x12, 0x34, 0x56, 0x78};
	int status;

	TEST_START;

	/* Compare empty array against a non-empty array */
	status = common_math_compare_array (NULL, sizeof (bytes), compare, sizeof (compare));
	CuAssertTrue (test, (status < 0));

	status = common_math_compare_array (bytes, 0, compare, sizeof (compare));
	CuAssertTrue (test, (status < 0));

	status = common_math_compare_array (NULL, 0, compare, sizeof (compare));
	CuAssertTrue (test, (status < 0));

	/* Compare a non-empty array against an empty array. */
	status = common_math_compare_array (bytes, sizeof (bytes), NULL, sizeof (compare));
	CuAssertTrue (test, (status > 0));

	status = common_math_compare_array (bytes, sizeof (bytes), compare, 0);
	CuAssertTrue (test, (status > 0));

	status = common_math_compare_array (bytes, sizeof (bytes), NULL, 0);
	CuAssertTrue (test, (status > 0));

	/* Compare two empty arrays */
	status = common_math_compare_array (NULL, sizeof (bytes), NULL, sizeof (compare));
	CuAssertIntEquals (test, 0, status);

	status = common_math_compare_array (bytes, 0, compare, 0);
	CuAssertIntEquals (test, 0, status);

	status = common_math_compare_array (NULL, sizeof (bytes), compare, 0);
	CuAssertIntEquals (test, 0, status);

	status = common_math_compare_array (bytes, 0, NULL, sizeof (compare));
	CuAssertIntEquals (test, 0, status);
}


// *INDENT-OFF*
TEST_SUITE_START (common_math);

TEST (common_math_test_saturing_increment_u8);
TEST (common_math_test_saturing_increment_u16);
TEST (common_math_test_saturing_increment_u32);
TEST (common_math_test_get_num_bits_set);
TEST (common_math_test_get_num_bits_set_before_index);
TEST (common_math_test_get_num_bits_set_before_index_out_of_range);
TEST (common_math_test_increment_byte_array_single_byte_zero_value);
TEST (common_math_test_increment_byte_array_single_byte_max_value_rolling_over);
TEST (common_math_test_increment_byte_array_multiple_bytes);
TEST (common_math_test_increment_byte_array_multiple_bytes_rolling_over_first_byte);
TEST (common_math_test_increment_byte_array_multiple_bytes_rolling_over_later_byte);
TEST (common_math_test_increment_byte_array_multiple_bytes_non_zero_after_rollover_byte);
TEST (common_math_test_increment_byte_array_multiple_bytes_max_value_rolling_over);
TEST (common_math_test_increment_byte_array_invalid_args);
TEST (common_math_test_increment_byte_array_single_byte_max_value_no_rolling_over);
TEST (common_math_test_increment_byte_array_multiple_bytes_max_value_no_rolling_over);
TEST (common_math_test_decrement_byte_array_single_byte);
TEST (common_math_test_decrement_byte_array_single_byte_zero_rolling_over);
TEST (common_math_test_decrement_byte_array_multiple_bytes);
TEST (common_math_test_decrement_byte_array_multiple_bytes_rolling_over_first_byte);
TEST (common_math_test_decrement_byte_array_multiple_bytes_rolling_over_later_byte);
TEST (common_math_test_decrement_byte_array_multiple_bytes_zero_rolling_over);
TEST (common_math_test_decrement_byte_array_null);
TEST (common_math_test_decrement_byte_array_single_byte_zero_no_rolling_over);
TEST (common_math_test_decrement_byte_array_multiple_bytes_zero_no_rolling_over);
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
TEST (common_math_test_get_num_bits_set_in_array_single_byte);
TEST (common_math_test_get_num_bits_set_in_array_multiple_bytes);
TEST (common_math_test_get_num_bits_set_in_array_zero_bytes);
TEST (common_math_test_get_num_bits_set_in_array_null);
TEST (common_math_test_get_num_contiguous_bits_set);
TEST (common_math_test_get_num_contiguous_bits_set_in_array_single_byte);
TEST (common_math_test_get_num_contiguous_bits_set_in_array_multiple_bytes);
TEST (common_math_test_get_num_contiguous_bits_set_in_array_zero_bytes);
TEST (common_math_test_get_num_contiguous_bits_set_in_array_null);
TEST (common_math_test_set_next_bit_in_array);
TEST (common_math_test_set_next_bit_in_array_first_bit);
TEST (common_math_test_set_next_bit_in_array_multiple_bytes);
TEST (common_math_test_set_next_bit_in_array_multiple_bytes_first_bit);
TEST (common_math_test_set_next_bit_in_array_null);
TEST (common_math_test_set_next_bit_in_array_zero_bytes);
TEST (common_math_test_set_next_bit_in_array_all_bits_sit);
TEST (common_math_test_set_next_bit_in_array_even_count);
TEST (common_math_test_set_next_bit_in_array_even_count_no_bits_set);
TEST (common_math_test_set_next_bit_in_array_even_count_multiple_bytes);
TEST (common_math_test_set_next_bit_in_array_even_count_multiple_bytes_no_bits_set);
TEST (common_math_test_set_next_bit_in_array_even_count_set_multiple_bits);
TEST (common_math_test_set_next_bit_in_array_even_count_zero_bytes);
TEST (common_math_test_set_next_bit_in_array_even_count_all_bits_set);
TEST (common_math_test_set_next_bit_in_array_even_count_null);
TEST (common_math_test_set_next_bit_in_array_odd_count);
TEST (common_math_test_set_next_bit_in_array_odd_count_no_bits_set);
TEST (common_math_test_set_next_bit_in_array_odd_count_multiple_bytes);
TEST (common_math_test_set_next_bit_in_array_odd_count_multiple_bytes_no_bits_set);
TEST (common_math_test_set_next_bit_in_array_odd_count_set_multiple_bits);
TEST (common_math_test_set_next_bit_in_array_odd_count_null);
TEST (common_math_test_set_next_bit_in_array_odd_count_zero_bytes);
TEST (common_math_test_set_next_bit_in_array_odd_count_all_bits_set);
TEST (common_math_test_is_array_zero);
TEST (common_math_test_is_array_zero_multiple_bytes);
TEST (common_math_test_is_array_zero_multiple_words);
TEST (common_math_test_is_array_zero_multiple_bytes_end_not_aligned);
TEST (common_math_test_is_array_zero_multiple_words_start_not_aligned);
TEST (common_math_test_is_array_zero_null);
TEST (common_math_test_is_array_zero_empty);
TEST (common_math_test_right_shift_array_single_byte);
TEST (common_math_test_right_shift_array_multiple_shift_less_than_one_byte);
TEST (common_math_test_right_shift_array_multiple_shift_more_than_one_byte);
TEST (common_math_test_right_shift_array_full_bytes);
TEST (common_math_test_right_shift_array_more_than_length);
TEST (common_math_test_right_shift_array_full_array);
TEST (common_math_test_right_shift_leave_one_bit);
TEST (common_math_test_right_shift_array_null);
TEST (common_math_test_right_shift_array_empty);
TEST (common_math_test_right_shift_array_no_shift);
TEST (common_math_test_left_shift_array_single_byte);
TEST (common_math_test_left_shift_array_multiple_shift_less_than_one_byte);
TEST (common_math_test_left_shift_array_multiple_shift_more_than_one_byte);
TEST (common_math_test_left_shift_array_full_bytes);
TEST (common_math_test_left_shift_array_more_than_length);
TEST (common_math_test_left_shift_array_full_array);
TEST (common_math_test_left_shift_leave_one_bit);
TEST (common_math_test_left_shift_array_null);
TEST (common_math_test_left_shift_array_empty);
TEST (common_math_test_left_shift_array_no_shift);
TEST (common_math_test_swap_bytes_uint16);
TEST (common_math_test_swap_bytes_uint32);
TEST (common_math_test_swap_bytes_uint64);
TEST (common_math_test_compare_array);
TEST (common_math_test_compare_array_multiple_bytes);
TEST (common_math_test_compare_array_zero_padded_reference);
TEST (common_math_test_compare_array_zero_padded_comparison);
TEST (common_math_test_compare_array_both_zero_padded);
TEST (common_math_test_compare_array_shorter_than_reference);
TEST (common_math_test_compare_array_shorter_than_reference_after_zero_padding);
TEST (common_math_test_compare_array_shorter_than_reference_with_zero_padding);
TEST (common_math_test_compare_array_longer_than_reference);
TEST (common_math_test_compare_array_longer_than_reference_after_zero_padding);
TEST (common_math_test_compare_array_longer_than_reference_with_zero_padding);
TEST (common_math_test_compare_array_empty_array);

TEST_SUITE_END;
// *INDENT-ON*
