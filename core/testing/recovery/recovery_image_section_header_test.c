// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "recovery/recovery_image_section_header.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/common/image_header_testing.h"
#include "testing/recovery/recovery_image_section_header_testing.h"


TEST_SUITE_LABEL ("recovery_image_section_header");


/**
 * Example section header using format 0.
 */
const uint8_t RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0[] = {
	0x10,0x00,0x00,0x00,0x31,0x2f,0x17,0x4b,0x00,0x04,0x00,0x00,0x00,0x00,0x08,0x00
};

const size_t RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN =
	sizeof (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0);

/**
 * The host write address in the example section header.
 */
const uint32_t RECOVERY_IMAGE_SECTION_HEADER_WRITE_ADDRESS = 0x400;

/**
 * The section image length in the example section header.
 */
const int RECOVERY_IMAGE_SECTION_HEADER_IMAGE_LENGTH = 0x80000;


/*******************
 * Test cases
 *******************/

static void recovery_image_section_header_test_init_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_init_unknown_format_max_length (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
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
	status |= mock_expect_output (&flash.mock, 1, max_header +
		IMAGE_HEADER_BASE_LEN, sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (NULL, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_section_header_init (&header, NULL, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_init_bad_marker (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN - 1] ^= 0x55;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_init_read_base_error (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_init_read_data_error (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_init_less_than_min_length (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_NOT_MINIMUM_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_init_format0_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_init_format0_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] += 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_init_unknown_format_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] -= 1;
	*((uint16_t*) &bad_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_init_unknown_format_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) bad_header) = 1025;
	*((uint16_t*) &bad_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_TOO_LONG, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_section_header_test_release_null (CuTest *test)
{
	TEST_START;

	recovery_image_section_header_release (NULL);
}

static void recovery_image_section_header_test_get_section_image_length_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	size_t length;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_get_section_image_length (&header, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_IMAGE_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_get_section_image_length_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t max_header[1024];
	size_t length;

	TEST_START;

	memcpy (max_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint32_t*) &max_header[12]) = 0x70000;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header +
		IMAGE_HEADER_BASE_LEN, sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_get_section_image_length (&header, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x70000, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_get_section_image_length_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_get_section_image_length (NULL, &length);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_section_header_get_section_image_length (&header, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_get_host_write_addr_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	uint32_t addr;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_get_host_write_addr (&header, &addr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_WRITE_ADDRESS, addr);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_get_host_write_addr_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	int status;
	uint8_t max_header[1024];
	uint32_t addr;

	TEST_START;

	memcpy (max_header, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint32_t*) &max_header[8]) = 0x300;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header +
		IMAGE_HEADER_BASE_LEN, sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_get_host_write_addr (&header, &addr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x300, addr);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_get_host_write_addr_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	uint32_t addr;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_get_host_write_addr (NULL, &addr);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_section_header_get_host_write_addr (&header, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_get_length (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	size_t length;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_get_length (&header, &length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}

static void recovery_image_section_header_test_get_length_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_section_header header;
	size_t length;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0,
		RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_SECTION_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_section_header_get_length (NULL, &length);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_section_header_get_length (&header, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_SECTION_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_section_header_release (&header);
}


TEST_SUITE_START (recovery_image_section_header);

TEST (recovery_image_section_header_test_init_format0);
TEST (recovery_image_section_header_test_init_unknown_format_max_length);
TEST (recovery_image_section_header_test_init_null);
TEST (recovery_image_section_header_test_init_bad_marker);
TEST (recovery_image_section_header_test_init_read_base_error);
TEST (recovery_image_section_header_test_init_read_data_error);
TEST (recovery_image_section_header_test_init_less_than_min_length);
TEST (recovery_image_section_header_test_init_format0_too_short);
TEST (recovery_image_section_header_test_init_format0_too_long);
TEST (recovery_image_section_header_test_init_unknown_format_too_short);
TEST (recovery_image_section_header_test_init_unknown_format_too_long);
TEST (recovery_image_section_header_test_release_null);
TEST (recovery_image_section_header_test_get_section_image_length_format0);
TEST (recovery_image_section_header_test_get_section_image_length_unknown_format);
TEST (recovery_image_section_header_test_get_section_image_length_null);
TEST (recovery_image_section_header_test_get_host_write_addr_format0);
TEST (recovery_image_section_header_test_get_host_write_addr_unknown_format);
TEST (recovery_image_section_header_test_get_host_write_addr_null);
TEST (recovery_image_section_header_test_get_length);
TEST (recovery_image_section_header_test_get_length_null);

TEST_SUITE_END;
