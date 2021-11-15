// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/firmware_header.h"
#include "common/image_header.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/common/image_header_testing.h"
#include "testing/firmware/firmware_header_testing.h"


TEST_SUITE_LABEL ("firmware_header");


/**
 * Example header using format 0.
 */
const uint8_t FIRMWARE_HEADER_FORMAT_0[] = {
	0x0a,0x00,0x00,0x00,0x47,0x4d,0x49,0x43,0x01,0x00
};

const size_t FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN = sizeof (FIRMWARE_HEADER_FORMAT_0);

/**
 * Example header using format 1.
 */
const uint8_t FIRMWARE_HEADER_FORMAT_1[] = {
	0x0b,0x00,0x01,0x00,0x47,0x4d,0x49,0x43,0x02,0x00,0x03
};

const size_t FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN = sizeof (FIRMWARE_HEADER_FORMAT_1);

/**
 * Example header using format 2.
 */
const uint8_t FIRMWARE_HEADER_FORMAT_2[] = {
	0x0d,0x00,0x02,0x00,0x47,0x4d,0x49,0x43,0x03,0x00,0x05,0x02,0x00
};

const size_t FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN = sizeof (FIRMWARE_HEADER_FORMAT_2);

/**
 * Example header using format 3.
 */
const uint8_t FIRMWARE_HEADER_FORMAT_3[] = {
	0x13,0x00,0x03,0x00,0x47,0x4d,0x49,0x43,0x04,0x00,0x06,0x03,0x00,0x44,0x33,0x22,0x11,0x00,0x02
};

const size_t FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN = sizeof (FIRMWARE_HEADER_FORMAT_3);


/*******************
 * Test cases
 *******************/

static void firmware_header_test_init_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_1,
		FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_1_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_1 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_1_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_format2 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_2,
		FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_2_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_2 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_2_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_format3 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_3,
		FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_3_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_3 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_3_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_unknown_format_max_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FIRMWARE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header + IMAGE_HEADER_BASE_LEN,
		sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (NULL, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = firmware_header_init (&header, NULL, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_init_bad_marker (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN - 1] ^= 0x55;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_init_read_base_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_init_read_data_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_init_less_than_min_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_NOT_MINIMUM_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_init_format0_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_0, FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_init_format0_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_0, FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] += 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_init_format1_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_1, FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN);
	bad_header[0] -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_format1_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_1, FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN);
	bad_header[0] += 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_format2_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_2, FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN);
	bad_header[0] -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_format2_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_2, FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN);
	bad_header[0] += 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_format3_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_3, FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN);
	bad_header[0] -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_format3_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_3, FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN);
	bad_header[0] += 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_init_unknown_format_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_3, FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN);
	bad_header[0] -= 1;
	*((uint16_t*) &bad_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FIRMWARE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_init_unknown_format_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FIRMWARE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) bad_header) = 1025;
	*((uint16_t*) &bad_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_TOO_LONG, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_header_test_release_null (CuTest *test)
{
	TEST_START;

	firmware_header_release (NULL);
}

static void firmware_header_test_get_recovery_revision_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_recovery_revision (&header, &revision);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, revision);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_recovery_revision_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_1,
		FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_1_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_1 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_1_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_recovery_revision (&header, &revision);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, revision);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_recovery_revision_format2 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_2,
		FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_2_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_2 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_2_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_recovery_revision (&header, &revision);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, revision);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_recovery_revision_format3 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_3,
		FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_3_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_3 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_3_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_recovery_revision (&header, &revision);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 4, revision);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_recovery_revision_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FIRMWARE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint16_t*) &max_header[8]) = 0x1234;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header + IMAGE_HEADER_BASE_LEN,
		sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_recovery_revision (&header, &revision);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x1234, revision);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_recovery_revision_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_recovery_revision (NULL, &revision);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INVALID_ARGUMENT, status);

	status = firmware_header_get_recovery_revision (&header, NULL);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_extra_images_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_1,
		FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_1_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_1 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_1_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_extra_images (&header);
	CuAssertIntEquals (test, 3, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_extra_images_format2 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_2,
		FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_2_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_2 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_2_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_extra_images (&header);
	CuAssertIntEquals (test, 5, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_extra_images_format3 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_3,
		FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_3_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_3 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_3_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_extra_images (&header);
	CuAssertIntEquals (test, 6, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_extra_images_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FIRMWARE_HEADER_FORMAT_1, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint8_t*) &max_header[10]) = 0x12;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header + IMAGE_HEADER_BASE_LEN,
		sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_extra_images (&header);
	CuAssertIntEquals (test, 0x12, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_extra_images_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_extra_images (NULL);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_extra_images_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_extra_images (&header);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INFO_NOT_AVAILABLE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_earliest_allowed_revision_format2 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_2,
		FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_2_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_2 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_2_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_earliest_allowed_revision (&header, &revision);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 2, revision);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_earliest_allowed_revision_format3 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_3,
		FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_3_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_3 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_3_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_earliest_allowed_revision (&header, &revision);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 3, revision);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_earliest_allowed_revision_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FIRMWARE_HEADER_FORMAT_2, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint16_t*) &max_header[11]) = 0x1234;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header + IMAGE_HEADER_BASE_LEN,
		sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_earliest_allowed_revision (&header, &revision);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x1234, revision);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_earliest_allowed_revision_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_earliest_allowed_revision (NULL, &revision);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INVALID_ARGUMENT, status);

	status = firmware_header_get_earliest_allowed_revision (&header, NULL);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_earliest_allowed_revision_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_earliest_allowed_revision (&header, &revision);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INFO_NOT_AVAILABLE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_earliest_allowed_revision_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	int revision;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_1,
		FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_1_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_1 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_1_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_earliest_allowed_revision (&header, &revision);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INFO_NOT_AVAILABLE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_signature_info_format3 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	size_t length;
	size_t signature;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_3,
		FIRMWARE_HEADER_FORMAT_3_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_3_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_3 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_3_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_signature_info (&header, &length, &signature);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x11223344, length);
	CuAssertIntEquals (test, 0x200, signature);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_signature_info_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	size_t length;
	size_t signature;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FIRMWARE_HEADER_FORMAT_3, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint32_t*) &max_header[13]) = 0x56789;
	*((uint32_t*) &max_header[17]) = 0x100;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header + IMAGE_HEADER_BASE_LEN,
		sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_signature_info (&header, &length, &signature);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x56789, length);
	CuAssertIntEquals (test, 0x100, signature);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_signature_info_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	size_t length;
	size_t signature;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_signature_info (NULL, &length, &signature);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INVALID_ARGUMENT, status);

	status = firmware_header_get_signature_info (&header, NULL, &signature);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INVALID_ARGUMENT, status);

	status = firmware_header_get_signature_info (&header, &length, NULL);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_signature_info_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	size_t length = 0;
	size_t signature = 0;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_0,
		FIRMWARE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_0 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_signature_info (&header, &length, &signature);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INFO_NOT_AVAILABLE, status);
	CuAssertIntEquals (test, 0, length);
	CuAssertIntEquals (test, 0, signature);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_signature_info_format1 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	size_t length = 0;
	size_t signature = 0;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_1,
		FIRMWARE_HEADER_FORMAT_1_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_1_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_1 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_1_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_signature_info (&header, &length, &signature);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INFO_NOT_AVAILABLE, status);
	CuAssertIntEquals (test, 0, length);
	CuAssertIntEquals (test, 0, signature);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}

static void firmware_header_test_get_signature_info_format2 (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_header header;
	int status;
	size_t length = 0;
	size_t signature = 0;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FIRMWARE_HEADER_FORMAT_2,
		FIRMWARE_HEADER_FORMAT_2_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FIRMWARE_HEADER_FORMAT_2_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FIRMWARE_HEADER_FORMAT_2 + IMAGE_HEADER_BASE_LEN, FIRMWARE_HEADER_FORMAT_2_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_header_get_signature_info (&header, &length, &signature);
	CuAssertIntEquals (test, FIRMWARE_HEADER_INFO_NOT_AVAILABLE, status);
	CuAssertIntEquals (test, 0, length);
	CuAssertIntEquals (test, 0, signature);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_header_release (&header);
}


TEST_SUITE_START (firmware_header);

TEST (firmware_header_test_init_format0);
TEST (firmware_header_test_init_format1);
TEST (firmware_header_test_init_format2);
TEST (firmware_header_test_init_format3);
TEST (firmware_header_test_init_unknown_format_max_length);
TEST (firmware_header_test_init_null);
TEST (firmware_header_test_init_bad_marker);
TEST (firmware_header_test_init_read_base_error);
TEST (firmware_header_test_init_read_data_error);
TEST (firmware_header_test_init_less_than_min_length);
TEST (firmware_header_test_init_format0_too_short);
TEST (firmware_header_test_init_format0_too_long);
TEST (firmware_header_test_init_format1_too_short);
TEST (firmware_header_test_init_format1_too_long);
TEST (firmware_header_test_init_format2_too_short);
TEST (firmware_header_test_init_format2_too_long);
TEST (firmware_header_test_init_format3_too_short);
TEST (firmware_header_test_init_format3_too_long);
TEST (firmware_header_test_init_unknown_format_too_short);
TEST (firmware_header_test_init_unknown_format_too_long);
TEST (firmware_header_test_release_null);
TEST (firmware_header_test_get_recovery_revision_format0);
TEST (firmware_header_test_get_recovery_revision_format1);
TEST (firmware_header_test_get_recovery_revision_format2);
TEST (firmware_header_test_get_recovery_revision_format3);
TEST (firmware_header_test_get_recovery_revision_unknown_format);
TEST (firmware_header_test_get_recovery_revision_null);
TEST (firmware_header_test_get_extra_images_format1);
TEST (firmware_header_test_get_extra_images_format2);
TEST (firmware_header_test_get_extra_images_format3);
TEST (firmware_header_test_get_extra_images_unknown_format);
TEST (firmware_header_test_get_extra_images_null);
TEST (firmware_header_test_get_extra_images_format0);
TEST (firmware_header_test_get_earliest_allowed_revision_format2);
TEST (firmware_header_test_get_earliest_allowed_revision_format3);
TEST (firmware_header_test_get_earliest_allowed_revision_unknown_format);
TEST (firmware_header_test_get_earliest_allowed_revision_null);
TEST (firmware_header_test_get_earliest_allowed_revision_format0);
TEST (firmware_header_test_get_earliest_allowed_revision_format1);
TEST (firmware_header_test_get_signature_info_format3);
TEST (firmware_header_test_get_signature_info_unknown_format);
TEST (firmware_header_test_get_signature_info_null);
TEST (firmware_header_test_get_signature_info_format0);
TEST (firmware_header_test_get_signature_info_format1);
TEST (firmware_header_test_get_signature_info_format2);

TEST_SUITE_END;
