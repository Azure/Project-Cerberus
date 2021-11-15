// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "firmware/app_image.h"
#include "flash/flash_util.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/engines/rsa_testing_engine.h"
#include "testing/crypto/rsa_testing.h"


TEST_SUITE_LABEL ("app_image");


/**
 * Test image data.
 */
static const uint8_t APP_IMAGE_DATA[] = {
	0x00,0x01,0x00,0x00,0x0a,0xae,0x96,0x39,0xd9,0x1e,0x07,0xb5,0x87,0xff,0xba,0x62,
	0xd1,0xbb,0xb9,0xec,0x78,0x3b,0x1e,0xc9,0x41,0x9a,0x2a,0x0f,0xe8,0x9b,0x37,0x2a,
	0x43,0x20,0x2b,0x86,0x96,0x63,0xab,0xb8,0x72,0x86,0xdf,0x3e,0xbe,0xe7,0x80,0xc8,
	0x1a,0x06,0x88,0x3f,0xc8,0x5e,0xb7,0x22,0x1e,0xb4,0x93,0xfb,0xfd,0x25,0xea,0xd5,
	0x25,0xa7,0x46,0xb7,0xbc,0x3d,0x8d,0xc1,0x9a,0xa2,0x89,0xef,0x20,0xfd,0xe5,0x36,
	0x72,0xf0,0x30,0x00,0xb0,0xfc,0x70,0x84,0x88,0x98,0x4f,0xd3,0x63,0x29,0x0e,0x2d,
	0xe8,0x84,0x33,0xdd,0x2d,0x17,0xaa,0x86,0xe9,0x9a,0xa1,0xd5,0xd4,0x0d,0xe0,0xec,
	0x0d,0x2a,0x02,0x94,0x90,0x88,0x0e,0xac,0x23,0xfc,0x7f,0xe9,0xb4,0xe8,0x3a,0xf2,
	0xa5,0x30,0xf6,0x1f,0xb6,0x73,0xc9,0xa9,0x5d,0x56,0x3a,0xff,0x21,0xe6,0xd8,0xc2,
	0x84,0xd0,0xad,0xe7,0x8a,0x69,0x62,0x2b,0x7d,0x46,0xfc,0x12,0x02,0xac,0x3e,0x5e,
	0x10,0xb8,0xea,0x5c,0x8b,0xb9,0x10,0x94,0x44,0x52,0xeb,0xc0,0x21,0xa2,0x73,0x72,
	0x46,0xa3,0xe8,0x16,0x2b,0x02,0xa8,0x98,0xc1,0xd0,0x79,0x17,0x7e,0xd5,0x74,0x66,
	0x90,0x26,0x57,0xd6,0x1b,0x81,0x20,0x4f,0x92,0x0e,0xfa,0x0f,0x21,0xc5,0x91,0x19,
	0xc2,0xfa,0x8c,0x56,0x23,0x25,0x99,0x7e,0xa5,0x76,0x8e,0x9a,0xbf,0xbb,0xa7,0x6d,
	0xa3,0x77,0x95,0x0a,0x89,0xfc,0x51,0x64,0x0d,0xf0,0x5c,0xdc,0x93,0xe4,0x3d,0xd6,
	0x56,0xc2,0x80,0xe7,0xf1,0xe0,0x7f,0x15,0x5b,0xc4,0xa9,0x56,0x12,0x94,0x0f,0x00,
	0xdc,0x7f,0x55,0x68,0x0b,0x22,0xef,0xa5,0xfa,0x25,0x1b,0x2e,0x31,0x81,0xa8,0x00,
	0xbe,0x2c,0x14,0xfa,0x24,0x01,0xc0,0x63,0xd7,0xe4,0x92,0x80,0x2f,0x18,0xdf,0xbf,
	0x8b,0x29,0xf2,0x60,0x11,0x77,0xec,0x96,0x99,0x2d,0x82,0x30,0x21,0x7b,0x53,0xe2,
	0x97,0x31,0x7b,0x94,0x67,0x19,0x3b,0x79,0xee,0x34,0xa9,0x89,0xec,0x02,0x11,0x86,
	0x1c,0x8c,0x50,0xe5,0x9e,0xab,0x09,0x1f,0x12,0xdb,0x59,0x24,0xc4,0xd0,0xf0,0x8c,
	0xd7,0x77,0x38,0x17,0x59,0xe1,0x6a,0x6c,0x5f,0x91,0x48,0x26,0x91,0x02,0x24,0xe2,
	0x9f,0x29,0xd1,0x17,0x5d,0xb7,0x8e,0xb1,0x66,0x4c,0x3e,0xc0,0x1a,0x0f,0x9d,0xeb,
	0x4e,0x07,0x9e,0x60,0xfe,0x46,0xbd,0x42,0x71,0x4f,0x2f,0x7e,0xa6,0xe1,0x3d,0x26,
	0x57,0x0d,0xf8,0x73,0x75,0xc6,0x3e,0xfc,0x74,0xc0,0x8e,0xb3,0x00,0xc9,0x18,0xb0,
	0xda,0xb5,0x96,0x84,0x02,0xcd,0x0b,0x6c,0xd5,0x74,0xcf,0xa7,0x51,0x7b,0xdc,0x68,
	0x48,0xb4,0x04,0x54,0x9c,0xd1,0x90,0xb2,0x48,0x9e,0x32,0x2e,0xfa,0xb8,0x48,0x9a,
	0x99,0x11,0xd3,0x63,0x34,0xc1,0x28,0x10,0x2e,0x78,0x0e,0xc3,0x34,0x33,0x72,0x61,
	0xc4,0x0d,0xe2,0x5a,0xe5,0x61,0xf0,0x5d,0xd5,0x6a,0x32,0xba,0x6a,0xf1,0x2c,0xf7,
	0x27,0xc5,0xb3,0xb6,0x11,0xf9,0xd5,0xc0,0x92,0xf6,0x29,0xa3,0xd2,0x06,0x67,0x73,
	0x00,0x30,0xb7,0x42,0xe0,0xff,0x17,0x28,0x43,0x65,0xe6,0x06,0x69,0xf5,0x9b,0x93,
	0xc3,0xd0,0x17,0x6f,0xb4,0xe3,0x51,0x11,0x5e,0xe5,0x8e,0x59,0xd5,0x9e,0x58,0x37,
	0xa1,0x4e,0xee,0xe9
};

/**
 * Test image data with an extra header.
 */
static const uint8_t APP_IMAGE_HEADER_DATA[] = {
	0x00,0x11,0x22,0x33,0x44,0x00,0x01,0x00,0x00,0x0a,0xae,0x96,0x39,0xd9,0x1e,0x07,
	0xb5,0x87,0xff,0xba,0x62,0xd1,0xbb,0xb9,0xec,0x78,0x3b,0x1e,0xc9,0x41,0x9a,0x2a,
	0x0f,0xe8,0x9b,0x37,0x2a,0x43,0x20,0x2b,0x86,0x96,0x63,0xab,0xb8,0x72,0x86,0xdf,
	0x3e,0xbe,0xe7,0x80,0xc8,0x1a,0x06,0x88,0x3f,0xc8,0x5e,0xb7,0x22,0x1e,0xb4,0x93,
	0xfb,0xfd,0x25,0xea,0xd5,0x25,0xa7,0x46,0xb7,0xbc,0x3d,0x8d,0xc1,0x9a,0xa2,0x89,
	0xef,0x20,0xfd,0xe5,0x36,0x72,0xf0,0x30,0x00,0xb0,0xfc,0x70,0x84,0x88,0x98,0x4f,
	0xd3,0x63,0x29,0x0e,0x2d,0xe8,0x84,0x33,0xdd,0x2d,0x17,0xaa,0x86,0xe9,0x9a,0xa1,
	0xd5,0xd4,0x0d,0xe0,0xec,0x0d,0x2a,0x02,0x94,0x90,0x88,0x0e,0xac,0x23,0xfc,0x7f,
	0xe9,0xb4,0xe8,0x3a,0xf2,0xa5,0x30,0xf6,0x1f,0xb6,0x73,0xc9,0xa9,0x5d,0x56,0x3a,
	0xff,0x21,0xe6,0xd8,0xc2,0x84,0xd0,0xad,0xe7,0x8a,0x69,0x62,0x2b,0x7d,0x46,0xfc,
	0x12,0x02,0xac,0x3e,0x5e,0x10,0xb8,0xea,0x5c,0x8b,0xb9,0x10,0x94,0x44,0x52,0xeb,
	0xc0,0x21,0xa2,0x73,0x72,0x46,0xa3,0xe8,0x16,0x2b,0x02,0xa8,0x98,0xc1,0xd0,0x79,
	0x17,0x7e,0xd5,0x74,0x66,0x90,0x26,0x57,0xd6,0x1b,0x81,0x20,0x4f,0x92,0x0e,0xfa,
	0x0f,0x21,0xc5,0x91,0x19,0xc2,0xfa,0x8c,0x56,0x23,0x25,0x99,0x7e,0xa5,0x76,0x8e,
	0x9a,0xbf,0xbb,0xa7,0x6d,0xa3,0x77,0x95,0x0a,0x89,0xfc,0x51,0x64,0x0d,0xf0,0x5c,
	0xdc,0x93,0xe4,0x3d,0xd6,0x56,0xc2,0x80,0xe7,0xf1,0xe0,0x7f,0x15,0x5b,0xc4,0xa9,
	0x56,0x12,0x94,0x0f,0x00,0xdc,0x7f,0x55,0x68,0xb3,0xaa,0x45,0x7e,0x5a,0x02,0xc3,
	0x52,0xad,0x7e,0xe1,0x00,0x5d,0x7e,0x17,0x38,0xb7,0x3e,0xe3,0x0a,0x5b,0x20,0xee,
	0x2a,0xe5,0xa5,0x6b,0x86,0xf2,0x1a,0x21,0x9c,0x98,0xaf,0x9f,0xd7,0x17,0x74,0x99,
	0x27,0xf4,0x78,0xfc,0x19,0xb9,0x42,0xeb,0xc5,0x1c,0xbb,0xb6,0x12,0x89,0xac,0xf5,
	0x4f,0x3c,0xe9,0x20,0x99,0x2a,0x2b,0xf0,0x6a,0x04,0xed,0x3e,0xa2,0xd4,0xb2,0xb2,
	0xda,0x76,0x50,0xe8,0x65,0x7a,0x6a,0x22,0x45,0x8a,0x2a,0xc4,0x26,0x3b,0xa9,0x6e,
	0x32,0xb0,0x17,0x54,0x36,0x7f,0x93,0x74,0xf1,0x48,0x58,0x24,0x6e,0xfb,0x1b,0x3a,
	0x9e,0x72,0xd7,0x6d,0x78,0x93,0x3a,0xa6,0x46,0x8b,0xf9,0xe5,0x1f,0xfb,0xb6,0x00,
	0x8b,0xfe,0xe4,0xe0,0x7f,0x2c,0xd2,0x41,0xff,0x58,0xca,0x76,0xb5,0x17,0xe5,0x27,
	0xf3,0xa0,0xc9,0x75,0x80,0xef,0x8a,0x57,0xc6,0x2c,0x4b,0xca,0xfb,0x32,0x1b,0x19,
	0xa2,0xac,0x2e,0xd3,0x84,0x17,0x90,0x2e,0xd0,0x30,0xd4,0x37,0x65,0x15,0x7e,0xca,
	0xea,0x11,0x03,0x53,0x3c,0x74,0x3e,0x5f,0x16,0xd2,0xee,0x44,0xe9,0xa8,0x45,0xaa,
	0xee,0x0f,0xce,0x69,0xdf,0x65,0x85,0x41,0xb8,0xb9,0x90,0xad,0xc0,0xbc,0x95,0x48,
	0x62,0xda,0xd5,0x97,0x6e,0x30,0x0d,0xcd,0xaa,0x28,0x30,0x00,0x1b,0x90,0x5e,0xc8,
	0x99,0x1d,0x50,0xf9,0xba,0xbb,0x65,0xd7,0x90,0x19,0x59,0xf7,0xab,0x74,0xc8,0x44,
	0x0a,0xdc,0xc0,0xcd,0x4e,0x51,0xfc,0x07,0x51,0x3b,0x90,0x79,0x57,0xa9,0x7f,0x87,
	0x8e,0xe2,0x34,0x32,0x6f,0x5b,0x0f,0x0c,0xec
};

/**
 * The length of the application image.
 */
static const size_t APP_IMAGE_DATA_LENGTH = 4 + 256;

/**
 * The length of the additional image header.
 */
static const size_t APP_IMAGE_HEADER_LENGTH = 5;

/**
 * The length of the application image with an additional header.
 */
static const size_t APP_IMAGE_HEADER_DATA_LENGTH = 5 + 4 + 256;

/**
 * The SHA256 hash of the test image data, not including the signature.
 */
static const uint8_t APP_IMAGE_HASH[] = {
	0x9e,0xf0,0x57,0x50,0x0e,0x51,0x57,0x20,0x49,0x52,0x41,0xbe,0x9a,0x00,0x47,0x87,
	0x2d,0x78,0x81,0x6c,0xe8,0xae,0xfa,0x28,0xc3,0x50,0xd4,0x10,0x67,0x6d,0xee,0xbb
};

/**
 * The SHA256 hash of the test image data with the additional header, not including the signature.
 */
static const uint8_t APP_IMAGE_HEADER_HASH[] = {
	0x1c,0xf3,0xad,0x24,0x4e,0x30,0x27,0xdc,0x45,0xe0,0x88,0xf9,0x1a,0xa9,0x2c,0x06,
	0x6c,0xe3,0x10,0xb6,0xfc,0x4c,0xa4,0x09,0x7a,0xc3,0x78,0x49,0x41,0x8f,0xb4,0x66
};

/**
 * The signature of the test image data.
 */
static const uint8_t *APP_IMAGE_SIGNATURE =
	APP_IMAGE_DATA + sizeof (APP_IMAGE_DATA) - APP_IMAGE_SIG_LENGTH;

/**
 * The signature of the test image data.
 */
static const uint8_t *APP_IMAGE_HEADER_SIGNATURE =
	APP_IMAGE_HEADER_DATA + sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_SIG_LENGTH;


/*******************
 * Test cases
 *******************/

static void app_image_test_get_length (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t img_length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_length (&flash.base, 0x10000, &img_length);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, APP_IMAGE_DATA_LENGTH - 4, img_length);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_length_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t img_length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_length (NULL, 0x10000, &img_length);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_get_length (&flash.base, 0x10000, NULL);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_length_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t img_length;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_length (&flash.base, 0x10000, &img_length);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_signature (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t sig_actual[RSA_ENCRYPT_LEN];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10104),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_signature (&flash.base, 0x10000, sig_actual, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_signature_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t sig_actual[RSA_ENCRYPT_LEN];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_signature (NULL, 0x10000, sig_actual, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_get_signature (&flash.base, 0x10000, NULL, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_signature_small_sig_buffer (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t sig_actual[RSA_ENCRYPT_LEN];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_signature (&flash.base, 0x10000, sig_actual, RSA_ENCRYPT_LEN - 1);
	CuAssertIntEquals (test, APP_IMAGE_SIG_BUFFER_TOO_SMALL, status);

	status = app_image_get_signature (&flash.base, 0x10000, sig_actual, 0);
	CuAssertIntEquals (test, APP_IMAGE_SIG_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_signature_read_length_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t sig_actual[RSA_ENCRYPT_LEN];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_signature (&flash.base, 0x10000, sig_actual, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_signature_read_signature_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t sig_actual[RSA_ENCRYPT_LEN];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10104), MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_signature (&flash.base, 0x10000, sig_actual, RSA_ENCRYPT_LEN);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_hash (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + offset,
		sizeof (APP_IMAGE_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash (&flash.base, 0x10000, &hash.base, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HASH, hash_actual, sizeof (APP_IMAGE_HASH));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash (NULL, 0x10000, &hash.base, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_get_hash (&flash.base, 0x10000, NULL, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_get_hash (&flash.base, 0x10000, &hash.base, NULL,
		sizeof (hash_actual));
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash (&flash.base, 0x10000, &hash.base, hash_actual,
		sizeof (hash_actual) - 1);
	CuAssertIntEquals (test, APP_IMAGE_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_read_length_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash (&flash.base, 0x10000, &hash.base, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_read_data_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash (&flash.base, 0x10000, &hash.base, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_verification (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20104),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + offset,
		sizeof (APP_IMAGE_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification (&flash.base, 0x20000, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20104),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + offset,
		sizeof (APP_IMAGE_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification (&flash.base, 0x20000, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HASH, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_no_match_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20104),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, RSA_SIGNATURE_BAD, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + offset,
		sizeof (APP_IMAGE_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification (&flash.base, 0x20000, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_verification (NULL, 0x20000, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_verification (&flash.base, 0x20000, NULL, &rsa.base, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_verification (&flash.base, 0x20000, &hash.base, NULL, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_verification (&flash.base, 0x20000, &hash.base, &rsa.base, NULL,
		NULL, 0);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_verification (&flash.base, 0x20000, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, APP_IMAGE_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_read_length_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification (&flash.base, 0x20000, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20104), MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification (&flash.base, 0x20000, &hash.base, &rsa.base, &RSA_PUBLIC_KEY,
		NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load (&flash.base, 0x20000, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, APP_IMAGE_DATA_LENGTH - 4, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_DATA + 4, load_data, app_len);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_load_no_length_out (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load (&flash.base, 0x20000, load_data, sizeof (load_data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_DATA + 4, load_data, APP_IMAGE_DATA_LENGTH - 4);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_load_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_load (NULL, 0x20000, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load (&flash.base, 0x20000, NULL, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_load_image_too_large (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH - 5];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load (&flash.base, 0x20000, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_load_length_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_load (&flash.base, 0x20000, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_load_image_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	size_t app_len;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20004), MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_load (&flash.base, 0x20000, load_data, sizeof (load_data), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_image_end (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t img_end;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_image_end (&flash.base, 0x10000, &img_end);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x10000 + sizeof (APP_IMAGE_DATA), img_end);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_image_end_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t img_end;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_image_end (NULL, 0x10000, &img_end);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_get_image_end (&flash.base, 0x10000, NULL);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_image_end_error (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t img_end;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_image_end (&flash.base, 0x10000, &img_end);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_data_addr (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t data_addr;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_data_addr (&flash.base, 0x10000, &data_addr);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x10004, data_addr);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_get_data_addr_null (CuTest *test)
{
	struct flash_mock flash;
	int status;
	uint32_t data_addr;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_data_addr (NULL, 0x10000, &data_addr);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_get_data_addr (&flash.base, 0x10000, NULL);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void app_image_test_load_and_verify (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, APP_IMAGE_DATA_LENGTH - 4, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_DATA + 4, load_data, APP_IMAGE_DATA_LENGTH - 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HASH, hash_out, sizeof (APP_IMAGE_HASH));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_bad_data (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t bad_data[APP_IMAGE_DATA_LENGTH];
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	memcpy (bad_data, APP_IMAGE_DATA, sizeof (bad_data));
	bad_data[5] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, bad_data, sizeof (bad_data), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, bad_data + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, NULL, 0, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, APP_IMAGE_DATA_LENGTH - 4, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_DATA + 4, load_data, APP_IMAGE_DATA_LENGTH - 4);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_no_length_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_DATA + 4, load_data, APP_IMAGE_DATA_LENGTH - 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HASH, hash_out, sizeof (APP_IMAGE_HASH));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (NULL, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, NULL, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		NULL, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, NULL, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, NULL, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_image_too_large (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH - 5];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_read_length_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_read_image_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20004), MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_start_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_update_hash_length_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_update_hash_image_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (4));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG (load_data), MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_update_finish_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (4));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (load_data),
		MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG (hash_out), MOCK_ARG (sizeof (hash_out)));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify (&flash.base, 0x20000, load_data, sizeof (load_data),
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20104 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + offset,
		sizeof (APP_IMAGE_HEADER_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_header_with_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	uint8_t hash_out[SHA256_HASH_LENGTH];
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20104 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + offset,
		sizeof (APP_IMAGE_HEADER_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HEADER_HASH, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_header_no_match_signature (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20104 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, RSA_SIGNATURE_BAD, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + offset,
		sizeof (APP_IMAGE_HEADER_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20104),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + offset,
		sizeof (APP_IMAGE_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, 0, &hash.base, &rsa.base,
		&RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_header_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_verification_with_header (NULL, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		NULL, &rsa.base, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, NULL, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, &rsa.base, NULL, NULL, 0);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_header_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out));
	CuAssertIntEquals (test, APP_IMAGE_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_header_read_length_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_verification_with_header_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20104 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_verification_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, &rsa.base, &RSA_PUBLIC_KEY, NULL, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_get_hash_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + offset,
		sizeof (APP_IMAGE_HEADER_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash_with_header (&flash.base, 0x10000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HEADER_HASH, hash_actual,
		sizeof (APP_IMAGE_HEADER_HASH));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_with_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];
	int offset = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	offset += FLASH_VERIFICATION_BLOCK;

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000 + offset),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - offset));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + offset,
		sizeof (APP_IMAGE_DATA) - offset, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash_with_header (&flash.base, 0x10000, 0, &hash.base, hash_actual,
		sizeof (hash_actual));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HASH, hash_actual, sizeof (APP_IMAGE_HASH));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_with_header_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash_with_header (NULL, 0x10000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_get_hash_with_header (&flash.base, 0x10000, APP_IMAGE_HEADER_LENGTH,
		NULL, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_get_hash_with_header (&flash.base, 0x10000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, NULL, sizeof (hash_actual));
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_with_header_small_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash_with_header (&flash.base, 0x10000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, hash_actual, sizeof (hash_actual) - 1);
	CuAssertIntEquals (test, APP_IMAGE_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_with_header_read_length_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash_with_header (&flash.base, 0x10000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_get_hash_with_header_read_data_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	struct flash_mock flash;
	int status;
	uint8_t hash_actual[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (FLASH_VERIFICATION_BLOCK));

	CuAssertIntEquals (test, 0, status);

	status = app_image_get_hash_with_header (&flash.base, 0x10000, APP_IMAGE_HEADER_LENGTH,
		&hash.base, hash_actual, sizeof (hash_actual));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
}

static void app_image_test_load_and_verify_with_header (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		load_data, APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HEADER_HASH, hash_out,
		sizeof (APP_IMAGE_HEADER_HASH));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_bad_data (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t bad_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	memcpy (bad_data, APP_IMAGE_HEADER_DATA, sizeof (bad_data));
	bad_data[15] ^= 0x55;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, bad_data + APP_IMAGE_HEADER_LENGTH,
		sizeof (bad_data) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, bad_data + 4 + APP_IMAGE_HEADER_LENGTH,
		sizeof (bad_data) - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, bad_data, sizeof (bad_data), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, RSA_ENGINE_BAD_SIGNATURE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_no_hash_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, NULL, 0, &app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		load_data, APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_no_length_out (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		load_data, APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HEADER_HASH, hash_out,
		sizeof (APP_IMAGE_HEADER_HASH));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_zero_length (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA, sizeof (APP_IMAGE_DATA), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20004),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_DATA_LENGTH - 4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_DATA + 4, APP_IMAGE_DATA_LENGTH - 4, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, 0, load_data,
		sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out, sizeof (hash_out),
		&app_len);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, APP_IMAGE_DATA_LENGTH - 4, app_len);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_DATA + 4, load_data, APP_IMAGE_DATA_LENGTH - 4);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (APP_IMAGE_HASH, hash_out, sizeof (APP_IMAGE_HASH));
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_null (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (NULL, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		NULL, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), NULL, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, NULL, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, NULL, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_small_hash_buffer (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH - 1];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_HASH_BUFFER_TOO_SMALL, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_image_too_large (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH - APP_IMAGE_HEADER_LENGTH - 5];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, APP_IMAGE_TOO_LARGE, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_read_length_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_read_image_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_read_signature_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_read_header_error (CuTest *test)
{
	HASH_TESTING_ENGINE hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = HASH_TESTING_ENGINE_INIT (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_READ_FAILED,
		MOCK_ARG (0x20000), MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&hash);
	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_start_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash,
		HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_hash_header_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_hash_length_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_NOT_NULL, MOCK_ARG (4));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_hash_image_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (4));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG (load_data),
		MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}

static void app_image_test_load_and_verify_with_header_finish_hash_error (CuTest *test)
{
	struct hash_engine_mock hash;
	RSA_TESTING_ENGINE rsa;
	struct flash_mock flash;
	int status;
	uint8_t load_data[APP_IMAGE_HEADER_DATA_LENGTH];
	uint8_t hash_out[SHA256_HASH_LENGTH];
	size_t app_len = 0;

	TEST_START;

	status = hash_mock_init (&hash);
	CuAssertIntEquals (test, 0, status);

	status = RSA_TESTING_ENGINE_INIT (&rsa);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_LENGTH), MOCK_ARG_NOT_NULL, MOCK_ARG (4));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA + APP_IMAGE_HEADER_LENGTH,
		sizeof (APP_IMAGE_HEADER_DATA) - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20004 + APP_IMAGE_HEADER_LENGTH),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1,
		APP_IMAGE_HEADER_DATA + 4 + APP_IMAGE_HEADER_LENGTH,
		APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x20000 + APP_IMAGE_HEADER_DATA_LENGTH), MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_SIG_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_SIGNATURE, RSA_ENCRYPT_LEN, 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x20000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect_output (&flash.mock, 1, APP_IMAGE_HEADER_DATA,
		sizeof (APP_IMAGE_HEADER_DATA), 2);

	status |= mock_expect (&hash.mock, hash.base.start_sha256, &hash, 0);
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG_NOT_NULL,
		MOCK_ARG (4));
	status |= mock_expect (&hash.mock, hash.base.update, &hash, 0, MOCK_ARG (load_data),
		MOCK_ARG (APP_IMAGE_HEADER_DATA_LENGTH - 4 - APP_IMAGE_HEADER_LENGTH));
	status |= mock_expect (&hash.mock, hash.base.finish, &hash, HASH_ENGINE_FINISH_FAILED,
		MOCK_ARG (hash_out), MOCK_ARG (sizeof (hash_out)));

	status |= mock_expect (&hash.mock, hash.base.cancel, &hash, 0);

	CuAssertIntEquals (test, 0, status);

	status = app_image_load_and_verify_with_header (&flash.base, 0x20000, APP_IMAGE_HEADER_LENGTH,
		load_data, sizeof (load_data), &hash.base, &rsa.base, &RSA_PUBLIC_KEY, hash_out,
		sizeof (hash_out), &app_len);
	CuAssertIntEquals (test, HASH_ENGINE_FINISH_FAILED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_validate_and_release (&hash);
	CuAssertIntEquals (test, 0, status);

	RSA_TESTING_ENGINE_RELEASE (&rsa);
}


TEST_SUITE_START (app_image);

TEST (app_image_test_get_length);
TEST (app_image_test_get_length_null);
TEST (app_image_test_get_length_error);
TEST (app_image_test_get_signature);
TEST (app_image_test_get_signature_null);
TEST (app_image_test_get_signature_small_sig_buffer);
TEST (app_image_test_get_signature_read_length_error);
TEST (app_image_test_get_signature_read_signature_error);
TEST (app_image_test_get_hash);
TEST (app_image_test_get_hash_null);
TEST (app_image_test_get_hash_small_buffer);
TEST (app_image_test_get_hash_read_length_error);
TEST (app_image_test_get_hash_read_data_error);
TEST (app_image_test_verification);
TEST (app_image_test_verification_with_hash_out);
TEST (app_image_test_verification_no_match_signature);
TEST (app_image_test_verification_null);
TEST (app_image_test_verification_small_hash_buffer);
TEST (app_image_test_verification_read_length_error);
TEST (app_image_test_verification_read_signature_error);
TEST (app_image_test_load);
TEST (app_image_test_load_no_length_out);
TEST (app_image_test_load_null);
TEST (app_image_test_load_image_too_large);
TEST (app_image_test_load_length_error);
TEST (app_image_test_load_image_error);
TEST (app_image_test_get_image_end);
TEST (app_image_test_get_image_end_null);
TEST (app_image_test_get_image_end_error);
TEST (app_image_test_get_data_addr);
TEST (app_image_test_get_data_addr_null);
TEST (app_image_test_load_and_verify);
TEST (app_image_test_load_and_verify_bad_data);
TEST (app_image_test_load_and_verify_no_hash_out);
TEST (app_image_test_load_and_verify_no_length_out);
TEST (app_image_test_load_and_verify_null);
TEST (app_image_test_load_and_verify_small_hash_buffer);
TEST (app_image_test_load_and_verify_image_too_large);
TEST (app_image_test_load_and_verify_read_length_error);
TEST (app_image_test_load_and_verify_read_image_error);
TEST (app_image_test_load_and_verify_read_signature_error);
TEST (app_image_test_load_and_verify_start_hash_error);
TEST (app_image_test_load_and_verify_update_hash_length_error);
TEST (app_image_test_load_and_verify_update_hash_image_error);
TEST (app_image_test_load_and_verify_update_finish_hash_error);
TEST (app_image_test_verification_with_header);
TEST (app_image_test_verification_with_header_with_hash_out);
TEST (app_image_test_verification_with_header_no_match_signature);
TEST (app_image_test_verification_with_header_zero_length);
TEST (app_image_test_verification_with_header_null);
TEST (app_image_test_verification_with_header_small_hash_buffer);
TEST (app_image_test_verification_with_header_read_length_error);
TEST (app_image_test_verification_with_header_read_signature_error);
TEST (app_image_test_get_hash_with_header);
TEST (app_image_test_get_hash_with_header_zero_length);
TEST (app_image_test_get_hash_with_header_null);
TEST (app_image_test_get_hash_with_header_small_buffer);
TEST (app_image_test_get_hash_with_header_read_length_error);
TEST (app_image_test_get_hash_with_header_read_data_error);
TEST (app_image_test_load_and_verify_with_header);
TEST (app_image_test_load_and_verify_with_header_bad_data);
TEST (app_image_test_load_and_verify_with_header_no_hash_out);
TEST (app_image_test_load_and_verify_with_header_no_length_out);
TEST (app_image_test_load_and_verify_with_header_zero_length);
TEST (app_image_test_load_and_verify_with_header_null);
TEST (app_image_test_load_and_verify_with_header_small_hash_buffer);
TEST (app_image_test_load_and_verify_with_header_image_too_large);
TEST (app_image_test_load_and_verify_with_header_read_length_error);
TEST (app_image_test_load_and_verify_with_header_read_image_error);
TEST (app_image_test_load_and_verify_with_header_read_signature_error);
TEST (app_image_test_load_and_verify_with_header_read_header_error);
TEST (app_image_test_load_and_verify_with_header_start_hash_error);
TEST (app_image_test_load_and_verify_with_header_hash_header_error);
TEST (app_image_test_load_and_verify_with_header_hash_length_error);
TEST (app_image_test_load_and_verify_with_header_hash_image_error);
TEST (app_image_test_load_and_verify_with_header_finish_hash_error);

TEST_SUITE_END;
