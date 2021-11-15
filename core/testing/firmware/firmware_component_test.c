// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/firmware_component.h"
#include "testing/mock/crypto/signature_verification_mock.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/common/image_header_testing.h"
#include "testing/firmware/firmware_component_testing.h"


TEST_SUITE_LABEL ("firmware_component");


/**
 * Test component image.
 */
const uint8_t FW_COMPONENT_DATA[] = {
	0x0e,0x00,0x00,0x00,0x78,0x56,0x34,0x12,0x03,0x01,0x00,0x00,0x00,0x01,0x01,0x00,
	0x01,0xc9,0x44,0x8c,0x40,0x6c,0x1f,0x64,0x8d,0xcb,0xa1,0xc7,0x3b,0x14,0xb4,0x89,
	0xd1,0x25,0x57,0x4a,0x5d,0xd5,0xaa,0x2c,0x1f,0x80,0x23,0x23,0xfc,0xc2,0xda,0xfc,
	0x7c,0xa6,0xad,0x35,0x83,0xab,0x92,0x1b,0x71,0x05,0xba,0x75,0x11,0x1e,0xdd,0x60,
	0x2a,0xe7,0xbe,0x91,0x3f,0xed,0xaa,0xe3,0x43,0x17,0x28,0x85,0x29,0xfd,0xb6,0x81,
	0x78,0x00,0xc0,0xe4,0xc1,0xb1,0x79,0x73,0x9e,0x91,0x5a,0x78,0x07,0x11,0x2a,0x24,
	0xd7,0xcc,0x22,0x35,0x2b,0xdf,0xbb,0xf7,0x62,0xdf,0x47,0x19,0xba,0x1f,0xbc,0x9a,
	0x5b,0x54,0xf5,0xa7,0x6a,0x39,0xcb,0x6b,0xe0,0xa5,0xb8,0x0a,0xa0,0x06,0x93,0xec,
	0xd8,0x03,0xbb,0x49,0x89,0xa8,0xfa,0x88,0x07,0x5e,0xc5,0x0f,0xad,0xb1,0xd1,0xa9,
	0x36,0x48,0x27,0x5f,0x40,0xa0,0x7c,0x2a,0x42,0x9c,0xdf,0x41,0x09,0x28,0xe0,0x05,
	0xad,0x51,0x44,0x96,0x98,0x34,0x7a,0x74,0xaa,0x9d,0xda,0x49,0x71,0xdd,0x6b,0xf0,
	0x74,0xf4,0x01,0xed,0x9d,0x42,0xd0,0x12,0x4a,0x63,0x7c,0xd0,0x6e,0x93,0x1f,0x9e,
	0xb6,0x40,0x93,0x23,0xa6,0x09,0xb7,0xac,0x2d,0x3e,0x79,0x8d,0x56,0x85,0x9f,0xc7,
	0x5a,0x58,0xa7,0x8f,0xdf,0x22,0x14,0x94,0x10,0x66,0xe6,0xd6,0xbb,0x2c,0x3f,0x05,
	0x63,0xb3,0x7a,0x64,0xf5,0x6d,0x52,0x82,0x82,0x3a,0x17,0x95,0x89,0xb1,0xb3,0x12,
	0x4d,0x21,0x64,0x4f,0x58,0xe9,0x4e,0x68,0xfa,0x5d,0x5e,0x80,0x49,0x78,0x70,0x4f,
	0x60,0xa3,0x59,0xca,0x3a,0xb0,0x04,0xb3,0xd2,0x34,0xae,0xac,0x7e,0xdc,0x17,0x16,
	0x81,0x16,0xef,0x27,0xac,0x73,0xbf,0xf5,0x72,0x5f,0xcd,0x32,0x48,0x23,0xf2,0x0c,
	0x4d,0x8c,0xed,0x93,0xab,0x5d,0x94,0x02,0x38,0x12,0xb6,0xd4,0xdf,0xa9,0xe7,0x1c,
	0x50,0xe1,0x7d,0x22,0xa2,0x7b,0xea,0xa7,0x3c,0x09,0x4b,0x8a,0xe8,0x15,0x3f,0x07,
	0xe3,0x76,0xfd,0x8c,0xa2,0xd3,0xd9,0x1a,0xbe,0x33,0x39,0x0c,0x9b,0xf3,0xa1,0x18,
	0x02,0xa5,0xb5,0x2a,0xb7,0xd8,0x17,0x4b,0xc3,0x31,0xff,0xa1,0xc9,0x09,0x45,0xa8,
	0xb7,0x5b,0x21,0x03,0x79,0xf8,0x1f,0x11,0xc1,0x3a,0xb2,0xcc,0xfc,0x63,0xfe,0x48,
	0x97,0x21,0x81,0x68,0x98,0xb4,0xb8,0x64,0xd5,0x57,0x69,0x87,0xac,0x1a,0xb6,0xea,
	0x01,0x40,0x47,0xa7,0x22,0x51,0x1b,0x28,0x73,0xd4,0x7b,0xdb,0x96,0xb3,0xe5,0xa4,
	0x26,0x9c,0xca,0xbe,0xd3,0xce,0x6b,0x7c,0xb5,0xd8,0xdb,0x78,0xbb,0x4e,0x1c,0x75,
	0xdf,0x8d,0x6e,0x00,0xf0,0x29,0xc4,0x05,0xe6,0x45,0xe1,0xd5,0xd1,0x62,0x57,0x49,
	0x63,0x53,0x1d,0xf5,0x91,0xfe,0xbe,0x1b,0x29,0x79,0xc9,0x60,0xab,0xea,0x9a,0xeb,
	0x2c,0x4e,0xf2,0xfc,0x5b,0x98,0x4a,0x52,0x44,0x89,0x85,0x9f,0x6e,0x97,0x03,0x21,
	0x4f,0xbb,0x1c,0x48,0xcd,0x53,0x46,0x36,0xf6,0xa3,0xb4,0xca,0xc1,0xaf,0x6d,0x7d,
	0xde,0x96,0x40,0x45,0x64,0x38,0x11,0xa1,0xe2,0xa7,0xbe,0x2c,0xfb,0x81,0x1e,0x7e,
	0xbf,0xb0,0x5f,0x3a,0xaf,0x35,0x73,0xf4,0x94,0xab,0x25,0x35,0x6e,0x96,0x36,0x36,
	0x75,0xcd,0x50,0xc1,0x67,0xbf,0x88,0x9e,0x3d,0x4d,0x9a,0xab,0xbd,0x8d,0x24,0xb2,
	0xd9
};

const size_t FW_COMPONENT_DATA_LEN = sizeof (FW_COMPONENT_DATA);

/**
 * Test component image with extra header data.
 */
const uint8_t FW_COMPONENT_HEADER_DATA[] = {
	0x00,0x11,0x22,0x33,0x44,0x55,0x0e,0x00,0x00,0x00,0x78,0x56,0x34,0x12,0x03,0x01,
	0x00,0x00,0x00,0x01,0x01,0x00,0x01,0xc9,0x44,0x8c,0x40,0x6c,0x1f,0x64,0x8d,0xcb,
	0xa1,0xc7,0x3b,0x14,0xb4,0x89,0xd1,0x25,0x57,0x4a,0x5d,0xd5,0xaa,0x2c,0x1f,0x80,
	0x23,0x23,0xfc,0xc2,0xda,0xfc,0x7c,0xa6,0xad,0x35,0x83,0xab,0x92,0x1b,0x71,0x05,
	0xba,0x75,0x11,0x1e,0xdd,0x60,0x2a,0xe7,0xbe,0x91,0x3f,0xed,0xaa,0xe3,0x43,0x17,
	0x28,0x85,0x29,0xfd,0xb6,0x81,0x78,0x00,0xc0,0xe4,0xc1,0xb1,0x79,0x73,0x9e,0x91,
	0x5a,0x78,0x07,0x11,0x2a,0x24,0xd7,0xcc,0x22,0x35,0x2b,0xdf,0xbb,0xf7,0x62,0xdf,
	0x47,0x19,0xba,0x1f,0xbc,0x9a,0x5b,0x54,0xf5,0xa7,0x6a,0x39,0xcb,0x6b,0xe0,0xa5,
	0xb8,0x0a,0xa0,0x06,0x93,0xec,0xd8,0x03,0xbb,0x49,0x89,0xa8,0xfa,0x88,0x07,0x5e,
	0xc5,0x0f,0xad,0xb1,0xd1,0xa9,0x36,0x48,0x27,0x5f,0x40,0xa0,0x7c,0x2a,0x42,0x9c,
	0xdf,0x41,0x09,0x28,0xe0,0x05,0xad,0x51,0x44,0x96,0x98,0x34,0x7a,0x74,0xaa,0x9d,
	0xda,0x49,0x71,0xdd,0x6b,0xf0,0x74,0xf4,0x01,0xed,0x9d,0x42,0xd0,0x12,0x4a,0x63,
	0x7c,0xd0,0x6e,0x93,0x1f,0x9e,0xb6,0x40,0x93,0x23,0xa6,0x09,0xb7,0xac,0x2d,0x3e,
	0x79,0x8d,0x56,0x85,0x9f,0xc7,0x5a,0x58,0xa7,0x8f,0xdf,0x22,0x14,0x94,0x10,0x66,
	0xe6,0xd6,0xbb,0x2c,0x3f,0x05,0x63,0xb3,0x7a,0x64,0xf5,0x6d,0x52,0x82,0x82,0x3a,
	0x17,0x95,0x89,0xb1,0xb3,0x12,0x4d,0x21,0x64,0x4f,0x58,0xe9,0x4e,0x68,0xfa,0x5d,
	0x5e,0x80,0x49,0x78,0x70,0x4f,0x60,0xa3,0x59,0xca,0x3a,0xb0,0x04,0xb3,0xd2,0x34,
	0xae,0xac,0x7e,0xdc,0x17,0x16,0x81,0x4a,0x03,0x53,0xda,0xae,0x52,0x00,0x7d,0x0f,
	0xc6,0x89,0x94,0x93,0x1a,0x79,0xf0,0xa8,0x39,0x76,0x99,0xe8,0x58,0x78,0x69,0x53,
	0x8f,0x2b,0x36,0x5d,0xa5,0xb6,0x43,0x90,0x64,0x54,0x77,0x71,0x4c,0x48,0x69,0x5e,
	0x68,0x05,0x77,0x49,0x0d,0x6a,0x46,0x6b,0x07,0x83,0xd2,0x0f,0x0e,0x91,0xbe,0x25,
	0xc0,0xce,0xfa,0xf1,0x99,0x44,0xed,0x97,0x95,0x5e,0x16,0x60,0x66,0x8e,0xf2,0x2e,
	0x21,0x55,0x3c,0x5a,0x5c,0xea,0x57,0xa7,0xfa,0x03,0xdd,0x92,0x6b,0xe7,0x0d,0x30,
	0x83,0x4a,0x54,0x3c,0xa6,0xb5,0x6c,0x5a,0x4a,0x98,0x31,0x60,0xcc,0x9d,0xcd,0x19,
	0x53,0x66,0xd1,0x34,0xf6,0xe7,0xa5,0x20,0x16,0xe2,0xdf,0x30,0x44,0x50,0xf7,0xc7,
	0x16,0x4c,0x2b,0xb3,0xf4,0xed,0xbf,0x07,0x9b,0x9d,0x82,0x9f,0x39,0xf5,0x3c,0x50,
	0xe3,0x03,0xeb,0x31,0xe3,0x60,0xdd,0xc3,0x85,0x30,0x52,0xc4,0xa0,0xf1,0xf7,0x68,
	0xd2,0x10,0xce,0xab,0xa8,0x4d,0x2e,0x2b,0xd9,0x62,0x92,0x89,0xe2,0x84,0x65,0xf3,
	0x43,0x50,0x17,0xdc,0x0a,0xa7,0x3e,0x31,0xab,0xd8,0x1c,0x86,0x53,0x04,0xcc,0x80,
	0xf3,0x22,0x3f,0x02,0x07,0xde,0xd3,0xed,0xce,0xa8,0xc6,0x9e,0x15,0xb6,0x0c,0x92,
	0x8d,0x11,0x01,0x33,0xed,0x1a,0xbf,0x72,0x89,0x9e,0x2d,0xb3,0xdc,0xfe,0x3a,0x05,
	0x2b,0x6e,0xc2,0x39,0xe5,0x7d,0x9f,0x41,0xdb,0xd1,0x75,0xa1,0xc9,0x84,0x63,0x62,
	0x85,0xee,0x84,0xa3,0x3c,0xe0,0xda,0xc9,0xde,0xf9,0x9a,0xf2,0x7e,0x11,0xb7,0xbf,
	0xd1,0x5f,0xb5,0xf2,0xe0,0xaa,0xd0
};

const size_t FW_COMPONENT_HEADER_DATA_LEN = sizeof (FW_COMPONENT_HEADER_DATA);

/**
 * Length of the extra header data on the component.
 */
#define	FW_COMPONENT_EXTRA_HDR_LENGTH	6

/**
 * The length of the component image, excluding the signature.
 */
static const size_t FW_COMPONENT_DATA_LENGTH = sizeof (FW_COMPONENT_DATA) - FW_COMPONENT_SIG_LENGTH;

/**
 * Offset in the data of the firmware component.
 */
#define	FW_COMPONENT_OFFSET			(FW_COMPONENT_HDR_LENGTH + IMAGE_HEADER_BASE_LEN)

/**
 * Length of just the component image, excluding header and signature bytes.
 */
static const size_t FW_COMPONENT_LENGTH = sizeof (FW_COMPONENT_DATA) - FW_COMPONENT_SIG_LENGTH -
	FW_COMPONENT_HDR_LENGTH - IMAGE_HEADER_BASE_LEN;

/**
 * The test component data.
 */
static const uint8_t *FW_COMPONENT = FW_COMPONENT_DATA + FW_COMPONENT_OFFSET;

/**
 * The SHA256 hash of the test component data, not including the signature.
 */
static const uint8_t FW_COMPONENT_HASH[] = {
	0x71,0x6b,0xcf,0x71,0xdd,0x7a,0x39,0xae,0x22,0x58,0x21,0xb8,0x8a,0x92,0xc6,0x7d,
	0xd6,0x6d,0x89,0x08,0xdc,0x3b,0xb8,0xcd,0xa0,0xd4,0x6e,0xb6,0x6f,0x91,0x5f,0x38
};

/**
 * Offset in the data of the signature.
 */
#define	FW_COMPONENT_SIG_OFFSET		((sizeof FW_COMPONENT_DATA) - FW_COMPONENT_SIG_LENGTH)

/**
 * The signature of the test component data.
 */
static const uint8_t *FW_COMPONENT_SIGNATURE = FW_COMPONENT_DATA + FW_COMPONENT_SIG_OFFSET;

/**
 * The length of the component image with an extra header, excluding the signature.
 */
static const size_t FW_COMPONENT_HEADER_DATA_LENGTH = sizeof (FW_COMPONENT_HEADER_DATA) -
	FW_COMPONENT_SIG_LENGTH;

/**
 * Offset in the data of the firmware component.
 */
#define	FW_COMPONENT_HEADER_OFFSET			(FW_COMPONENT_EXTRA_HDR_LENGTH + FW_COMPONENT_HDR_LENGTH + IMAGE_HEADER_BASE_LEN)

/**
 * Length of just the component image, excluding all header and signature bytes.
 */
static const size_t FW_COMPONENT_HEADER_LENGTH = sizeof (FW_COMPONENT_HEADER_DATA) -
	FW_COMPONENT_SIG_LENGTH - FW_COMPONENT_HDR_LENGTH - IMAGE_HEADER_BASE_LEN -
	FW_COMPONENT_EXTRA_HDR_LENGTH;

/**
 * The test component data with an extra header.
 */
static const uint8_t *FW_COMPONENT_HEADER = FW_COMPONENT_HEADER_DATA + FW_COMPONENT_HEADER_OFFSET;

/**
 * The SHA256 hash of the test component data with an extra header, not including the signature.
 */
static const uint8_t FW_COMPONENT_HEADER_HASH[] = {
	0x19,0x82,0x53,0xcf,0x56,0xad,0xe0,0xa1,0x4d,0xd9,0x0d,0x81,0x03,0x2a,0x4a,0x60,
	0xe8,0x13,0x08,0x8b,0x58,0x50,0x27,0x82,0xf1,0x8d,0x46,0x93,0x98,0x10,0xcd,0x91
};

/**
 * Offset in the data of the signature.
 */
#define	FW_COMPONENT_HEADER_SIG_OFFSET		((sizeof FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_SIG_LENGTH)

/**
 * The signature of the test component data.
 */
static const uint8_t *FW_COMPONENT_HEADER_SIGNATURE = FW_COMPONENT_HEADER_DATA +
	FW_COMPONENT_HEADER_SIG_OFFSET;


/*******************
 * Test cases
 *******************/

static void firmware_component_test_init (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_unknown_header_format_max_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
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

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (NULL, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_init (&image, NULL, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_bad_marker (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER + 1);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_read_base_header_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_read_header_data_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_less_than_min_header_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, IMAGE_HEADER_NOT_MINIMUM_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_header_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_header_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH + 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_unknown_header_format_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH - 1;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_unknown_header_format_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1025;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, IMAGE_HEADER_TOO_LONG, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_with_header_unknown_header_format_max_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1024;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + 3), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (max_header) - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header + IMAGE_HEADER_BASE_LEN,
		sizeof (max_header) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_init_with_header_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (NULL, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_init_with_header (&image, NULL, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_bad_marker (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000,
		FW_COMPONENT_MARKER + 1, FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_read_base_header_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_read_header_data_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_less_than_min_header_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, IMAGE_HEADER_NOT_MINIMUM_SIZE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_header_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH - 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_header_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t bad_header[IMAGE_HEADER_BASE_LEN];

	TEST_START;

	memcpy (bad_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	bad_header[0] = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH + 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_unknown_header_format_too_short (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = IMAGE_HEADER_BASE_LEN + FW_COMPONENT_HDR_LENGTH - 1;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_BAD_HEADER, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_init_with_header_unknown_header_format_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t max_header[1024];

	TEST_START;

	memcpy (max_header, FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN);
	*((uint16_t*) max_header) = 1025;
	*((uint16_t*) &max_header[2]) = 0xffff;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + 3),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, max_header, sizeof (max_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		3);
	CuAssertIntEquals (test, IMAGE_HEADER_TOO_LONG, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void firmware_component_test_release_null (CuTest *test)
{
	TEST_START;

	firmware_component_release (NULL);
}

static void firmware_component_test_get_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_length_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_length_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_length_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_length (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void firmware_component_test_get_signature_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_signature_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_length_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_signature_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_length_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_signature_length (&image);
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_length_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_signature_length (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void firmware_component_test_get_signature (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, status);

	status = testing_validate_array (FW_COMPONENT_SIGNATURE, sig_actual, FW_COMPONENT_SIG_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, status);

	status = testing_validate_array (FW_COMPONENT_HEADER_SIGNATURE, sig_actual,
		FW_COMPONENT_SIG_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FW_COMPONENT_SIG_LENGTH, status);

	status = testing_validate_array (FW_COMPONENT_SIGNATURE, sig_actual, FW_COMPONENT_SIG_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (NULL, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_get_signature (&image, NULL, sizeof (sig_actual));
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_small_sig_buffer (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, FW_COMPONENT_SIG_LENGTH - 1);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_SIG_BUFFER_TOO_SMALL, status);

	status = firmware_component_get_signature (&image, sig_actual, 0);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_SIG_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_signature_read_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t sig_actual[FW_COMPONENT_SIG_LENGTH * 2];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG (&sig_actual),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_signature (&image, sig_actual, sizeof (sig_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		sizeof (FW_COMPONENT_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		sizeof (FW_COMPONENT_HEADER_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HEADER_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA + offset,
		sizeof (FW_COMPONENT_HEADER_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HEADER_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_with_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		sizeof (FW_COMPONENT_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (NULL, &hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_get_hash (&image, NULL, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_get_hash (&image, &hash.base, NULL, sizeof (hash_actual));
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, SHA256_HASH_LENGTH - 1);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_get_hash_read_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_get_hash (&image, &hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		sizeof (FW_COMPONENT_DATA) - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		sizeof (FW_COMPONENT_DATA) - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		sizeof (FW_COMPONENT_HEADER_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HEADER_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA + offset,
		sizeof (FW_COMPONENT_HEADER_DATA) - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_with_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		sizeof (FW_COMPONENT_DATA) - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (NULL, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_verification (&image, NULL, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_verification (&image, &hash.base, NULL, NULL, 0);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, hash_actual,
		SHA256_HASH_LENGTH - 1);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_read_data_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_verification_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + offset,
		sizeof (FW_COMPONENT_DATA) - offset, 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_verification (&image, &hash.base, &verification.base, NULL, 0);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_no_length_out (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_HEADER_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_HEADER, load_data, FW_COMPONENT_HEADER_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (NULL, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load (&image, NULL, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_image_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[FW_COMPONENT_LENGTH - 1];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = firmware_component_load (&image, load_data, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_image_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load (&image, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_image_end (&image);
	CuAssertIntEquals (test, 0x10000 + sizeof (FW_COMPONENT_DATA), length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_image_end (&image);
	CuAssertIntEquals (test, 0x10000 + sizeof (FW_COMPONENT_HEADER_DATA), length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	length = firmware_component_get_image_end (&image);
	CuAssertIntEquals (test, 0x10000 + sizeof (FW_COMPONENT_DATA), length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_image_end_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_image_end (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void firmware_component_test_get_data_addr (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t address;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	address = firmware_component_get_data_addr (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_OFFSET, address);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_data_addr_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t address;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	address = firmware_component_get_data_addr (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_HEADER_OFFSET, address);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_data_addr_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	uint32_t address;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	address = firmware_component_get_data_addr (&image);
	CuAssertIntEquals (test, 0x10000 + FW_COMPONENT_OFFSET, address);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_get_data_addr_null (CuTest *test)
{
	size_t length;

	TEST_START;

	length = firmware_component_get_data_addr (NULL);
	CuAssertIntEquals (test, 0, length);
}

static void firmware_component_test_load_and_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, NULL, 0, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_no_length_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), NULL);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		sizeof (FW_COMPONENT_HEADER_DATA), 2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_HEADER_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT_HEADER, load_data, FW_COMPONENT_HEADER_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HEADER_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_with_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		0, MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = testing_validate_array (FW_COMPONENT, load_data, FW_COMPONENT_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (NULL, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify (&image, NULL, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), NULL,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		NULL, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH - 1];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_image_too_large (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[FW_COMPONENT_LENGTH - 1];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = firmware_component_load_and_verify (&image, load_data, 0, &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_image_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_verify_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&verification.mock, verification.base.verify_signature, &verification,
		SIG_VERIFICATION_VERIFY_SIG_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HASH, SHA256_HASH_LENGTH),
		MOCK_ARG (SHA256_HASH_LENGTH),
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH),
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, SIG_VERIFICATION_VERIFY_SIG_FAILED, status);

	status = testing_validate_array (FW_COMPONENT_HASH, hash_actual, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void firmware_component_test_load_and_verify_hash_start_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_hash_header_info_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_hash_header_data_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_hash_image_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT, FW_COMPONENT_LENGTH), MOCK_ARG (FW_COMPONENT_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_hash_finish_error (CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT, FW_COMPONENT_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_SIGNATURE, FW_COMPONENT_SIG_LENGTH,
		2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN, FW_COMPONENT_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT, FW_COMPONENT_LENGTH), MOCK_ARG (FW_COMPONENT_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_with_header_read_extra_header_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_load_and_verify_with_header_hash_extra_header_error (
	CuTest *test)
{
	struct hash_engine_mock hash;
	struct flash_mock flash;
	struct firmware_component image;
	struct signature_verification_mock verification;
	int status;
	uint8_t load_data[sizeof (FW_COMPONENT_DATA)];
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_init (&verification);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_OFFSET), MOCK_ARG (load_data),
		MOCK_ARG (FW_COMPONENT_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH,
		2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_HEADER_SIG_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_SIGNATURE,
		FW_COMPONENT_SIG_LENGTH, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_HEADER_DATA,
		sizeof (FW_COMPONENT_HEADER_DATA), 2);

	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (FW_COMPONENT_HEADER_DATA, FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG (FW_COMPONENT_EXTRA_HDR_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_load_and_verify (&image, load_data, sizeof (load_data), &hash.base,
		&verification.base, hash_actual, sizeof (hash_actual), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = signature_verification_mock_validate_and_release (&verification);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_no_length_out (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_HEADER_OFFSET, FW_COMPONENT_HEADER, FW_COMPONENT_HEADER_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (NULL, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_copy (&image, NULL, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_image_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, FW_COMPONENT_LENGTH - 1,
		&app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_copy_copy_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_destination_matches (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_no_length_out (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_with_header (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_HEADER_OFFSET,
		FW_COMPONENT, &flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_HEADER_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_with_header_destination_matches (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + FW_COMPONENT_EXTRA_HDR_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - FW_COMPONENT_EXTRA_HDR_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		FW_COMPONENT_HEADER_DATA + IMAGE_HEADER_BASE_LEN + FW_COMPONENT_EXTRA_HDR_LENGTH,
		sizeof (FW_COMPONENT_HEADER_DATA) - IMAGE_HEADER_BASE_LEN - FW_COMPONENT_EXTRA_HDR_LENGTH,
		2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		FW_COMPONENT_EXTRA_HDR_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_HEADER_OFFSET,
		FW_COMPONENT, &flash, 0x40000, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_with_header_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init_with_header (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER,
		0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= flash_mock_expect_copy_flash_verify (&flash, &flash, 0x40000,
		0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT, FW_COMPONENT_LENGTH);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FW_COMPONENT_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_null (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (NULL, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = firmware_component_compare_and_copy (&image, NULL, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_image_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000,
		FW_COMPONENT_LENGTH - 1, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0, &app_len);
	CuAssertIntEquals (test, FIRMWARE_COMPONENT_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_compare_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + FW_COMPONENT_OFFSET), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}

static void firmware_component_test_compare_and_copy_copy_error (CuTest *test)
{
	struct flash_mock flash;
	struct firmware_component image;
	int status;
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA, sizeof (FW_COMPONENT_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FW_COMPONENT_HDR_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, FW_COMPONENT_DATA + IMAGE_HEADER_BASE_LEN,
		sizeof (FW_COMPONENT_DATA) - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_init (&image, &flash.base, 0x10000, FW_COMPONENT_MARKER);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_verify_copy (&flash, 0x10000 + FW_COMPONENT_OFFSET, FW_COMPONENT,
		&flash, 0x40000, FW_COMPONENT_DATA, FLASH_VERIFICATION_BLOCK);
	status |= flash_mock_expect_erase_flash (&flash, 0x40000, 0x10000);
	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = firmware_component_compare_and_copy (&image, &flash.base, 0x40000, 0x10000, &app_len);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	firmware_component_release (&image);
}


TEST_SUITE_START (firmware_component);

TEST (firmware_component_test_init);
TEST (firmware_component_test_init_unknown_header_format_max_length);
TEST (firmware_component_test_init_null);
TEST (firmware_component_test_init_bad_marker);
TEST (firmware_component_test_init_read_base_header_error);
TEST (firmware_component_test_init_read_header_data_error);
TEST (firmware_component_test_init_less_than_min_header_length);
TEST (firmware_component_test_init_header_too_short);
TEST (firmware_component_test_init_header_too_long);
TEST (firmware_component_test_init_unknown_header_format_too_short);
TEST (firmware_component_test_init_unknown_header_format_too_long);
TEST (firmware_component_test_init_with_header);
TEST (firmware_component_test_init_with_header_unknown_header_format_max_length);
TEST (firmware_component_test_init_with_header_zero_length);
TEST (firmware_component_test_init_with_header_null);
TEST (firmware_component_test_init_with_header_bad_marker);
TEST (firmware_component_test_init_with_header_read_base_header_error);
TEST (firmware_component_test_init_with_header_read_header_data_error);
TEST (firmware_component_test_init_with_header_less_than_min_header_length);
TEST (firmware_component_test_init_with_header_header_too_short);
TEST (firmware_component_test_init_with_header_header_too_long);
TEST (firmware_component_test_init_with_header_unknown_header_format_too_short);
TEST (firmware_component_test_init_with_header_unknown_header_format_too_long);
TEST (firmware_component_test_release_null);
TEST (firmware_component_test_get_length);
TEST (firmware_component_test_get_length_with_header);
TEST (firmware_component_test_get_length_with_header_zero_length);
TEST (firmware_component_test_get_length_null);
TEST (firmware_component_test_get_signature_length);
TEST (firmware_component_test_get_signature_length_with_header);
TEST (firmware_component_test_get_signature_length_with_header_zero_length);
TEST (firmware_component_test_get_signature_length_null);
TEST (firmware_component_test_get_signature);
TEST (firmware_component_test_get_signature_with_header);
TEST (firmware_component_test_get_signature_with_header_zero_length);
TEST (firmware_component_test_get_signature_null);
TEST (firmware_component_test_get_signature_small_sig_buffer);
TEST (firmware_component_test_get_signature_read_error);
TEST (firmware_component_test_get_hash);
TEST (firmware_component_test_get_hash_with_header);
TEST (firmware_component_test_get_hash_with_header_zero_length);
TEST (firmware_component_test_get_hash_null);
TEST (firmware_component_test_get_hash_small_buffer);
TEST (firmware_component_test_get_hash_read_error);
TEST (firmware_component_test_verification);
TEST (firmware_component_test_verification_with_hash_out);
TEST (firmware_component_test_verification_with_header);
TEST (firmware_component_test_verification_with_header_zero_length);
TEST (firmware_component_test_verification_null);
TEST (firmware_component_test_verification_small_hash_buffer);
TEST (firmware_component_test_verification_read_signature_error);
TEST (firmware_component_test_verification_read_data_error);
TEST (firmware_component_test_verification_verify_error);
TEST (firmware_component_test_load);
TEST (firmware_component_test_load_no_length_out);
TEST (firmware_component_test_load_with_header);
TEST (firmware_component_test_load_with_header_zero_length);
TEST (firmware_component_test_load_null);
TEST (firmware_component_test_load_image_too_large);
TEST (firmware_component_test_load_image_error);
TEST (firmware_component_test_get_image_end);
TEST (firmware_component_test_get_image_end_with_header);
TEST (firmware_component_test_get_image_end_with_header_zero_length);
TEST (firmware_component_test_get_image_end_null);
TEST (firmware_component_test_get_data_addr);
TEST (firmware_component_test_get_data_addr_with_header);
TEST (firmware_component_test_get_data_addr_with_header_zero_length);
TEST (firmware_component_test_get_data_addr_null);
TEST (firmware_component_test_load_and_verify);
TEST (firmware_component_test_load_and_verify_no_hash_out);
TEST (firmware_component_test_load_and_verify_no_length_out);
TEST (firmware_component_test_load_and_verify_with_header);
TEST (firmware_component_test_load_and_verify_with_header_zero_length);
TEST (firmware_component_test_load_and_verify_null);
TEST (firmware_component_test_load_and_verify_small_hash_buffer);
TEST (firmware_component_test_load_and_verify_image_too_large);
TEST (firmware_component_test_load_and_verify_image_error);
TEST (firmware_component_test_load_and_verify_read_signature_error);
TEST (firmware_component_test_load_and_verify_verify_error);
TEST (firmware_component_test_load_and_verify_hash_start_error);
TEST (firmware_component_test_load_and_verify_hash_header_info_error);
TEST (firmware_component_test_load_and_verify_hash_header_data_error);
TEST (firmware_component_test_load_and_verify_hash_image_error);
TEST (firmware_component_test_load_and_verify_hash_finish_error);
TEST (firmware_component_test_load_and_verify_with_header_read_extra_header_error);
TEST (firmware_component_test_load_and_verify_with_header_hash_extra_header_error);
TEST (firmware_component_test_copy);
TEST (firmware_component_test_copy_no_length_out);
TEST (firmware_component_test_copy_with_header);
TEST (firmware_component_test_copy_with_header_zero_length);
TEST (firmware_component_test_copy_null);
TEST (firmware_component_test_copy_image_too_large);
TEST (firmware_component_test_copy_erase_error);
TEST (firmware_component_test_copy_copy_error);
TEST (firmware_component_test_compare_and_copy);
TEST (firmware_component_test_compare_and_copy_destination_matches);
TEST (firmware_component_test_compare_and_copy_no_length_out);
TEST (firmware_component_test_compare_and_copy_with_header);
TEST (firmware_component_test_compare_and_copy_with_header_destination_matches);
TEST (firmware_component_test_compare_and_copy_with_header_zero_length);
TEST (firmware_component_test_compare_and_copy_null);
TEST (firmware_component_test_compare_and_copy_image_too_large);
TEST (firmware_component_test_compare_and_copy_compare_error);
TEST (firmware_component_test_compare_and_copy_erase_error);
TEST (firmware_component_test_compare_and_copy_copy_error);

TEST_SUITE_END;
