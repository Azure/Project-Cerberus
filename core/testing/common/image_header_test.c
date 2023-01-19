// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "common/image_header.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/engines/hash_testing_engine.h"
#include "testing/common/image_header_testing.h"


TEST_SUITE_LABEL ("image_header");


/**
 * Image header for testing.
 */
const uint8_t IMAGE_HEADER_TEST[] = {
	0x0d,0x00,0x02,0x00,0x47,0x4d,0x49,0x43,0x11,0x22,0x33,0x44,0x55
};

const size_t IMAGE_HEADER_TEST_LEN = sizeof (IMAGE_HEADER_TEST);

/**
 * SHA1 digest of IMAGE_HEADER_TEST.
 */
const uint8_t IMAGE_HEADER_TEST_SHA1[] = {
	0x73,0x72,0x1d,0x14,0x8a,0xa8,0x92,0xed,0x25,0x1d,0x50,0x11,0xb7,0x7d,0x9b,0x32,
	0xc9,0x7c,0xcb,0xb0
};

/**
 * SHA256 digest of IMAGE_HEADER_TEST.
 */
const uint8_t IMAGE_HEADER_TEST_SHA256[] = {
	0x16,0xca,0x9e,0x6d,0x22,0x3a,0xf3,0xbf,0x82,0x7b,0x4a,0xa3,0x7a,0x52,0x4b,0x69,
	0x8c,0xec,0xf9,0xbb,0x21,0xd3,0xeb,0xd8,0xba,0xd3,0x03,0x27,0xe1,0x23,0x6a,0xe2
};

/**
 * SHA384 digest of IMAGE_HEADER_TEST.
 */
const uint8_t IMAGE_HEADER_TEST_SHA384[] = {
	0xac,0xd2,0xf9,0xc5,0x24,0x9b,0x16,0x3a,0x12,0x9a,0x3b,0xf4,0xe7,0x47,0x48,0x76,
	0xe0,0x64,0xc7,0xf8,0xe0,0x0d,0x91,0xfc,0xcb,0x81,0xa3,0x8f,0xcc,0x75,0xd9,0x5b,
	0x81,0x34,0x21,0x56,0x23,0xe9,0x8a,0x22,0x47,0xbf,0x6b,0x3a,0xd4,0x96,0x63,0x83
};

/**
 * SHA512 digest of IMAGE_HEADER_TEST.
 */
const uint8_t IMAGE_HEADER_TEST_SHA512[] = {
	0x83,0xf7,0x0b,0x6c,0xc6,0xa3,0x19,0x95,0xfb,0xce,0x30,0x2e,0x84,0x0b,0xff,0x05,
	0x00,0x39,0x33,0xfb,0xc1,0x09,0x6a,0xc3,0x1e,0x90,0x12,0x48,0x88,0xeb,0xab,0x0a,
	0xd5,0xd9,0xb7,0xf7,0x24,0x64,0xfa,0x37,0x36,0xfc,0x5f,0x0d,0xea,0xb1,0xc7,0x0a,
	0xc9,0x92,0xae,0x6e,0x0c,0x99,0x3a,0x1a,0x53,0xfa,0x65,0x08,0xde,0xba,0xbf,0xa7
};


/**
 * Dependencies for testing.
 */
struct image_header_testing {
	HASH_TESTING_ENGINE hash;				/**< Hash engine for testing. */
	struct hash_engine_mock hash_mock;		/**< Mock for hash operations. */
	struct flash_mock flash;				/**< Mock for the updater flash device. */
	struct image_header test;				/**< Image header for testing. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param header Testing dependencies to initialize.
 */
static void image_header_testing_init_dependencies (CuTest *test,
	struct image_header_testing *header)
{
	int status;

	status = HASH_TESTING_ENGINE_INIT (&header->hash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&header->hash_mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_init (&header->flash);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param header Testing dependencies to release.
 */
static void image_header_testing_release_dependencies (CuTest *test,
	struct image_header_testing *header)
{
	int status;

	status = flash_mock_validate_and_release (&header->flash);
	status |= hash_mock_validate_and_release (&header->hash_mock);

	CuAssertIntEquals (test, 0, status);

	HASH_TESTING_ENGINE_RELEASE (&header->hash);
}

/**
 * Initialize an image header for testing.
 *
 * @param test The test framework.
 * @param header Testing dependencies.
 * @param addr Address of the header data on flash.
 * @param data The header data
 * @param length Length of the header data.
 * @param marker Marker identifying the header.
 */
static void image_header_testing_init (CuTest *test, struct image_header_testing *header,
	uint32_t addr, const uint8_t *data, size_t length, uint32_t marker)
{
	int status;

	image_header_testing_init_dependencies (test, header);

	status = mock_expect (&header->flash.mock, header->flash.base.read, &header->flash, 0,
		MOCK_ARG (addr), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&header->flash.mock, 1, data, length, 2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_init (&header->test, &header->flash.base, addr, marker, length);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize an image header for testing and load the header data.
 *
 * @param test The test framework.
 * @param header Testing dependencies.
 * @param addr Address of the header data on flash.
 * @param data The header data
 * @param length Length of the header data.
 * @param marker Marker identifying the header.
 */
static void image_header_testing_init_and_load (CuTest *test, struct image_header_testing *header,
	uint32_t addr, const uint8_t *data, size_t length, uint32_t marker)
{
	int status;

	image_header_testing_init (test, header, addr, data, length, marker);

	status = mock_expect (&header->flash.mock, header->flash.base.read, &header->flash, 0,
		MOCK_ARG (addr + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (length - IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&header->flash.mock, 1, &data[IMAGE_HEADER_BASE_LEN],
		length - IMAGE_HEADER_BASE_LEN, 2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_load_data (&header->test, &header->flash.base, addr);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, header->test.data);
}

/**
 * Release image header test components and validate all mocks.
 *
 * @param test The test framework.
 * @param header Testing components to release.
 */
static void image_header_testing_release (CuTest *test, struct image_header_testing *header)
{
	image_header_testing_release_dependencies (test, header);
	image_header_release (&header->test);
}


/*******************
 * Test cases
 *******************/

static void image_header_test_init (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init_dependencies (test, &header);

	status = mock_expect (&header.flash.mock, header.flash.base.read, &header.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&header.flash.mock, 1, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN,
		2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_init (&header.test, &header.flash.base, 0x10000, IMAGE_HEADER_TEST_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, 0, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_init_null (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init_dependencies (test, &header);

	status = image_header_init (NULL, &header.flash.base, 0x10000, IMAGE_HEADER_TEST_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = image_header_init (&header.test, NULL, 0x10000, IMAGE_HEADER_TEST_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	image_header_testing_release_dependencies (test, &header);
}

static void image_header_test_init_read_error (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init_dependencies (test, &header);

	status = mock_expect (&header.flash.mock, header.flash.base.read, &header.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x20000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = image_header_init (&header.test, &header.flash.base, 0x20000, IMAGE_HEADER_TEST_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	image_header_testing_release_dependencies (test, &header);
}

static void image_header_test_init_header_too_short (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t bad_header[IMAGE_HEADER_TEST_LEN];

	TEST_START;

	memcpy (bad_header, IMAGE_HEADER_TEST, sizeof (bad_header));
	bad_header[0] = IMAGE_HEADER_BASE_LEN - 1;		// Total length shorter than base info.

	image_header_testing_init_dependencies (test, &header);

	status = mock_expect (&header.flash.mock, header.flash.base.read, &header.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&header.flash.mock, 1, bad_header, sizeof (bad_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_init (&header.test, &header.flash.base, 0x10000, IMAGE_HEADER_TEST_MARKER,
		IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, IMAGE_HEADER_NOT_MINIMUM_SIZE, status);

	image_header_testing_release_dependencies (test, &header);
}

static void image_header_test_init_bad_marker (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init_dependencies (test, &header);

	status = mock_expect (&header.flash.mock, header.flash.base.read, &header.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&header.flash.mock, 1, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN,
		2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_init (&header.test, &header.flash.base, 0x10000,
		IMAGE_HEADER_TEST_MARKER + 1, IMAGE_HEADER_TEST_LEN);
	CuAssertIntEquals (test, IMAGE_HEADER_BAD_MARKER, status);

	image_header_testing_release_dependencies (test, &header);
}

static void image_header_test_init_header_too_long (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init_dependencies (test, &header);

	status = mock_expect (&header.flash.mock, header.flash.base.read, &header.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (IMAGE_HEADER_BASE_LEN));
	status |= mock_expect_output (&header.flash.mock, 1, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN,
		2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_init (&header.test, &header.flash.base, 0x10000, IMAGE_HEADER_TEST_MARKER,
		IMAGE_HEADER_TEST_LEN - 1);
	CuAssertIntEquals (test, IMAGE_HEADER_TOO_LONG, status);

	image_header_testing_release_dependencies (test, &header);
}

static void image_header_test_load_data (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init (test, &header, 0x10000, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN,
		IMAGE_HEADER_TEST_MARKER);

	status = mock_expect (&header.flash.mock, header.flash.base.read, &header.flash, 0,
		MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));
	status |= mock_expect_output (&header.flash.mock, 1, &IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
		IMAGE_HEADER_TEST_DATA_LENGTH, 2);

	CuAssertIntEquals (test, 0, status);

	status = image_header_load_data (&header.test, &header.flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertPtrNotNull (test, header.test.data);

	status = testing_validate_array (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN], header.test.data,
		IMAGE_HEADER_TEST_DATA_LENGTH);
	CuAssertIntEquals (test, 0, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_load_data_null (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init (test, &header, 0x10000, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN,
		IMAGE_HEADER_TEST_MARKER);

	status = image_header_load_data (NULL, &header.flash.base, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = image_header_load_data (&header.test, NULL, 0x10000);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_load_data_read_error (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init (test, &header, 0x10000, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN,
		IMAGE_HEADER_TEST_MARKER);

	status = mock_expect (&header.flash.mock, header.flash.base.read, &header.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + IMAGE_HEADER_BASE_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (IMAGE_HEADER_TEST_LEN - IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = image_header_load_data (&header.test, &header.flash.base, 0x10000);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);
	CuAssertPtrEquals (test, NULL, header.test.data);

	image_header_testing_release (test, &header);
}

static void image_header_test_get_length (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init (test, &header, 0x10000, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN,
		IMAGE_HEADER_TEST_MARKER);

	status = image_header_get_length (&header.test);
	CuAssertIntEquals (test, IMAGE_HEADER_TEST_LEN, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_get_length_null (CuTest *test)
{
	int status;

	TEST_START;

	status = image_header_get_length (NULL);
	CuAssertIntEquals (test, 0, status);
}

static void image_header_test_get_format (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init (test, &header, 0x10000, IMAGE_HEADER_TEST, IMAGE_HEADER_TEST_LEN,
		IMAGE_HEADER_TEST_MARKER);

	status = image_header_get_format (&header.test);
	CuAssertIntEquals (test, IMAGE_HEADER_TEST_FORMAT, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_get_format_null (CuTest *test)
{
	int status;

	TEST_START;

	status = image_header_get_format (NULL);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);
}

static void image_header_test_hash_header_sha1 (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA1_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = image_header_hash_header (&header.test, &header.hash.base, HASH_TYPE_SHA1, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (IMAGE_HEADER_TEST_SHA1, digest, SHA1_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_sha256 (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = image_header_hash_header (&header.test, &header.hash.base, HASH_TYPE_SHA256, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (IMAGE_HEADER_TEST_SHA256, digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_sha384 (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA384_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = image_header_hash_header (&header.test, &header.hash.base, HASH_TYPE_SHA384, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (IMAGE_HEADER_TEST_SHA384, digest, SHA384_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_sha512 (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA512_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = image_header_hash_header (&header.test, &header.hash.base, HASH_TYPE_SHA512, digest,
		sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (IMAGE_HEADER_TEST_SHA512, digest, SHA512_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_null (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = image_header_hash_header (NULL, &header.hash.base, HASH_TYPE_SHA256, digest,
		sizeof (digest));
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = image_header_hash_header (&header.test, NULL, HASH_TYPE_SHA256, digest,
		sizeof (digest));
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = image_header_hash_header (&header.test, &header.hash.base, HASH_TYPE_SHA256, NULL,
		sizeof (digest));
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = image_header_hash_header (&header.test, &header.hash.base, HASH_TYPE_SHA256, digest,
		0);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_unknown_hash (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = image_header_hash_header (&header.test, &header.hash.base, (enum hash_type) 5, digest,
		sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UNKNOWN_HASH, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_small_hash_buffer (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH - 1];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = image_header_hash_header (&header.test, &header.hash.base, HASH_TYPE_SHA256, digest,
		sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_HASH_BUFFER_TOO_SMALL, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_start_error (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = mock_expect (&header.hash_mock.mock, header.hash_mock.base.start_sha256,
		&header.hash_mock, HASH_ENGINE_START_SHA256_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = image_header_hash_header (&header.test, &header.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_START_SHA256_FAILED, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_update_info_error (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = mock_expect (&header.hash_mock.mock, header.hash_mock.base.start_sha256,
		&header.hash_mock, 0);

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.update, &header.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.cancel, &header.hash_mock,
		0);

	CuAssertIntEquals (test, 0, status);

	status = image_header_hash_header (&header.test, &header.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_update_data_error (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = mock_expect (&header.hash_mock.mock, header.hash_mock.base.start_sha256,
		&header.hash_mock, 0);

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.update, &header.hash_mock,
		0, MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.update, &header.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.cancel, &header.hash_mock,
		0);

	CuAssertIntEquals (test, 0, status);

	status = image_header_hash_header (&header.test, &header.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_header_finish_error (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = mock_expect (&header.hash_mock.mock, header.hash_mock.base.start_sha256,
		&header.hash_mock, 0);

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.update, &header.hash_mock,
		0, MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.update, &header.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.cancel, &header.hash_mock,
		0);

	CuAssertIntEquals (test, 0, status);

	status = image_header_hash_header (&header.test, &header.hash_mock.base, HASH_TYPE_SHA256,
		digest, sizeof (digest));
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_update_header (CuTest *test)
{
	struct image_header_testing header;
	int status;
	uint8_t digest[SHA256_HASH_LENGTH];

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = header.hash.base.start_sha256 (&header.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = image_header_hash_update_header (&header.test, &header.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = header.hash.base.finish (&header.hash.base, digest, sizeof (digest));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (IMAGE_HEADER_TEST_SHA256, digest, SHA256_HASH_LENGTH);
	CuAssertIntEquals (test, 0, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_update_header_null (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = image_header_hash_update_header (NULL, &header.hash.base);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	status = image_header_hash_update_header (&header.test, NULL);
	CuAssertIntEquals (test, IMAGE_HEADER_INVALID_ARGUMENT, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_update_header_update_info_error (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = mock_expect (&header.hash_mock.mock, header.hash_mock.base.update, &header.hash_mock,
		HASH_ENGINE_UPDATE_FAILED, MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	CuAssertIntEquals (test, 0, status);

	status = image_header_hash_update_header (&header.test, &header.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	image_header_testing_release (test, &header);
}

static void image_header_test_hash_update_header_update_data_error (CuTest *test)
{
	struct image_header_testing header;
	int status;

	TEST_START;

	image_header_testing_init_and_load (test, &header, 0x10000, IMAGE_HEADER_TEST,
		IMAGE_HEADER_TEST_LEN, IMAGE_HEADER_TEST_MARKER);

	status = mock_expect (&header.hash_mock.mock, header.hash_mock.base.update, &header.hash_mock,
		0, MOCK_ARG_PTR_CONTAINS (IMAGE_HEADER_TEST, IMAGE_HEADER_BASE_LEN),
		MOCK_ARG (IMAGE_HEADER_BASE_LEN));

	status |= mock_expect (&header.hash_mock.mock, header.hash_mock.base.update, &header.hash_mock,
		HASH_ENGINE_UPDATE_FAILED,
		MOCK_ARG_PTR_CONTAINS (&IMAGE_HEADER_TEST[IMAGE_HEADER_BASE_LEN],
			IMAGE_HEADER_TEST_DATA_LENGTH),
		MOCK_ARG (IMAGE_HEADER_TEST_DATA_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = image_header_hash_update_header (&header.test, &header.hash_mock.base);
	CuAssertIntEquals (test, HASH_ENGINE_UPDATE_FAILED, status);

	image_header_testing_release (test, &header);
}


TEST_SUITE_START (image_header);

TEST (image_header_test_init);
TEST (image_header_test_init_null);
TEST (image_header_test_init_read_error);
TEST (image_header_test_init_header_too_short);
TEST (image_header_test_init_bad_marker);
TEST (image_header_test_init_header_too_long);
TEST (image_header_test_load_data);
TEST (image_header_test_load_data_null);
TEST (image_header_test_load_data_read_error);
TEST (image_header_test_get_length);
TEST (image_header_test_get_length_null);
TEST (image_header_test_get_format);
TEST (image_header_test_get_format_null);
TEST (image_header_test_hash_header_sha1);
TEST (image_header_test_hash_header_sha256);
TEST (image_header_test_hash_header_sha384);
TEST (image_header_test_hash_header_sha512);
TEST (image_header_test_hash_header_null);
TEST (image_header_test_hash_header_unknown_hash);
TEST (image_header_test_hash_header_small_hash_buffer);
TEST (image_header_test_hash_header_start_error);
TEST (image_header_test_hash_header_update_info_error);
TEST (image_header_test_hash_header_update_data_error);
TEST (image_header_test_hash_header_finish_error);
TEST (image_header_test_hash_update_header);
TEST (image_header_test_hash_update_header_null);
TEST (image_header_test_hash_update_header_update_info_error);
TEST (image_header_test_hash_update_header_update_data_error);

TEST_SUITE_END;
