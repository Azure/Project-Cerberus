// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "recovery/recovery_image_header.h"
#include "cmd_interface/cerberus_protocol.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/common/image_header_testing.h"
#include "testing/recovery/recovery_image_header_testing.h"
#include "testing/recovery/recovery_image_testing.h"


TEST_SUITE_LABEL ("recovery_image_header");


/**
 * Example header using format 0.
 */
const uint8_t RECOVERY_IMAGE_HEADER_FORMAT_0[] = {
	0x40,0x00,0x00,0x00,0x29,0x7c,0x14,0x8a,0x56,0x65,0x72,0x73,0x69,0x6f,0x6e,0x20,
	0x54,0x65,0x73,0x74,0x31,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x04,0x00,0x00,0x00,0x01,0x00,0x00,
	0x0f,0x50,0x6c,0x61,0x74,0x66,0x6f,0x72,0x6d,0x20,0x54,0x65,0x73,0x74,0x31,0x00
};

const size_t RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN = sizeof (RECOVERY_IMAGE_HEADER_FORMAT_0);

const char *RECOVERY_IMAGE_HEADER_PLATFORM_ID = "Platform Test1";

const char *RECOVERY_IMAGE_HEADER_VERSION_ID = "Version Test1";

#define RECOVERY_IMAGE_HEADER_IMAGE_LEN		(64 + 848 + 256)


/*******************
 * Test cases
 *******************/

static void recovery_image_header_test_init_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_init_unknown_format_max_length (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, RECOVERY_IMAGE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
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

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (NULL, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_header_init (&header, NULL, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_bad_marker (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN - 1] ^= 0x55;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_read_base_error (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_read_data_error (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_less_than_min_length (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_NOT_MINIMUM_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN - 1));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN - 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] += 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN + 1));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN + 1, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_unknown_format_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[0] -= (RECOVERY_IMAGE_HEADER_PLATFORM_ID_LEN + 2);
	*((uint16_t*) &bad_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN -
			(RECOVERY_IMAGE_HEADER_PLATFORM_ID_LEN + 2)));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN -
		(RECOVERY_IMAGE_HEADER_PLATFORM_ID_LEN + 2), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_unknown_format_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) bad_header) = 1025;
	*((uint16_t*) &bad_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_TOO_LONG, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_platform_id_length_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 8] -= 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_platform_id_length_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 8] += 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_platform_id_no_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN-1] = 'x';

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_platform_id_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 9] = '\0';

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_platform_id_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 10] = '\0';

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_PLATFORM_ID, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_platform_id_length_less_than_min_length (
	CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 8] = 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_FORMAT_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_version_id_no_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];
	int i;

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);

	for (i = IMAGE_HEADER_BASE_LEN + RECOVERY_IMAGE_HEADER_VERSION_ID_LEN;
		i < IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN; i++) {
		bad_header[i] = 'x';
	}

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_version_id_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN] = '\0';

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_VERSION_ID, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_sig_longer_than_image (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	*((uint32_t*) &bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 4]) =
		0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_sig_same_length_as_image (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 4] =
		(uint8_t) (RECOVERY_IMAGE_DATA_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 5] =
		RECOVERY_IMAGE_DATA_LEN >> 8;
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 6] =
		RECOVERY_IMAGE_DATA_LEN >> 16;
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 7] =
		RECOVERY_IMAGE_DATA_LEN >> 24;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_init_format0_sig_length_into_header (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	uint8_t bad_header[RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN];

	TEST_START;

	memcpy (bad_header, RECOVERY_IMAGE_HEADER_FORMAT_0, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 4] =
		(uint8_t) (RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + 1);
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 5] =
		(RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + 1) >> 8;
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 6] =
		(RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + 1) >> 16;
	bad_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 7] =
		(RECOVERY_IMAGE_DATA_LEN - RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN + 1) >> 24;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (bad_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header +
		IMAGE_HEADER_BASE_LEN, sizeof (bad_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_BAD_IMAGE_LENGTH, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void recovery_image_header_test_release_null (CuTest *test)
{
	TEST_START;

	recovery_image_header_release (NULL);
}

static void recovery_image_header_test_get_version_id_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	char *version_id;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_version_id (&header, &version_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, version_id);
	CuAssertStrEquals (test, RECOVERY_IMAGE_HEADER_VERSION_ID, version_id);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_version_id_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	char *version_id;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, RECOVERY_IMAGE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	strcpy((char*) &max_header[8], "test1");

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

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_version_id (&header, &version_id);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, version_id);
	CuAssertStrEquals (test, "test1", version_id);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_version_id_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	char *version_id;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_version_id (NULL, &version_id);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_header_get_version_id (&header, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_platform_id_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	char *id;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_platform_id (&header, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, RECOVERY_IMAGE_HEADER_PLATFORM_ID, id);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_platform_id_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	char *id;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, RECOVERY_IMAGE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint8_t*) &max_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 8]) =
		strlen ("test1") + 1;
	strcpy((char*) &max_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 9],
		"test1");

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

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_platform_id (&header, &id);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, id);
	CuAssertStrEquals (test, "test1", id);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_platform_id_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	char *id;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_platform_id (NULL, &id);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_header_get_platform_id (&header, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_image_length_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	size_t len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_image_length (&header, &len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_IMAGE_LEN, len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_image_length_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	size_t len;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, RECOVERY_IMAGE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint32_t*) &max_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN]) = 0x7a120;

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

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_image_length (&header, &len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x7a120, len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_image_length_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	size_t len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_image_length (NULL, &len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_header_get_image_length (&header, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_signature_length_format0 (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	size_t len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_signature_length (&header, &len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_SIGNATURE_LEN, len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_signature_length_unknown_format (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	size_t len;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, RECOVERY_IMAGE_HEADER_FORMAT_0, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;
	*((uint32_t*) &max_header[IMAGE_HEADER_BASE_LEN + CERBERUS_PROTOCOL_FW_VERSION_LEN + 4]) = 128;

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

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_signature_length (&header, &len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 128, len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_signature_length_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	size_t len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_signature_length (NULL, &len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_header_get_signature_length (&header, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_length (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	size_t len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_length (&header, &len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}

static void recovery_image_header_test_get_length_null (CuTest *test)
{
	struct flash_mock flash;
	struct recovery_image_header header;
	int status;
	size_t len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0,
		RECOVERY_IMAGE_HEADER_FORMAT_0_TOTAL_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (RECOVERY_IMAGE_HEADER_FORMAT_0_LEN));
	status |= mock_expect_output (&flash.mock, 1, RECOVERY_IMAGE_HEADER_FORMAT_0 +
		IMAGE_HEADER_BASE_LEN, RECOVERY_IMAGE_HEADER_FORMAT_0_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_init (&header, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = recovery_image_header_get_length (NULL, &len);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = recovery_image_header_get_length (&header, NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	recovery_image_header_release (&header);
}


TEST_SUITE_START (recovery_image_header);

TEST (recovery_image_header_test_init_format0);
TEST (recovery_image_header_test_init_unknown_format_max_length);
TEST (recovery_image_header_test_init_null);
TEST (recovery_image_header_test_init_bad_marker);
TEST (recovery_image_header_test_init_read_base_error);
TEST (recovery_image_header_test_init_read_data_error);
TEST (recovery_image_header_test_init_less_than_min_length);
TEST (recovery_image_header_test_init_format0_too_short);
TEST (recovery_image_header_test_init_format0_too_long);
TEST (recovery_image_header_test_init_unknown_format_too_short);
TEST (recovery_image_header_test_init_unknown_format_too_long);
TEST (recovery_image_header_test_init_format0_platform_id_length_too_short);
TEST (recovery_image_header_test_init_format0_platform_id_length_too_long);
TEST (recovery_image_header_test_init_format0_platform_id_no_null);
TEST (recovery_image_header_test_init_format0_platform_id_null);
TEST (recovery_image_header_test_init_format0_platform_id_too_short);
TEST (recovery_image_header_test_init_format0_platform_id_length_less_than_min_length);
TEST (recovery_image_header_test_init_format0_version_id_no_null);
TEST (recovery_image_header_test_init_format0_version_id_null);
TEST (recovery_image_header_test_init_format0_sig_longer_than_image);
TEST (recovery_image_header_test_init_format0_sig_same_length_as_image);
TEST (recovery_image_header_test_init_format0_sig_length_into_header);
TEST (recovery_image_header_test_release_null);
TEST (recovery_image_header_test_get_version_id_format0);
TEST (recovery_image_header_test_get_version_id_unknown_format);
TEST (recovery_image_header_test_get_version_id_null);
TEST (recovery_image_header_test_get_platform_id_format0);
TEST (recovery_image_header_test_get_platform_id_unknown_format);
TEST (recovery_image_header_test_get_platform_id_null);
TEST (recovery_image_header_test_get_image_length_format0);
TEST (recovery_image_header_test_get_image_length_unknown_format);
TEST (recovery_image_header_test_get_image_length_null);
TEST (recovery_image_header_test_get_signature_length_format0);
TEST (recovery_image_header_test_get_signature_length_unknown_format);
TEST (recovery_image_header_test_get_signature_length_null);
TEST (recovery_image_header_test_get_length);
TEST (recovery_image_header_test_get_length_null);

TEST_SUITE_END;
