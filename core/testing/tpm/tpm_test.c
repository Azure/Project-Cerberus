// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "platform.h"
#include "testing.h"
#include "tpm/tpm.h"
#include "testing/mock/flash/flash_store_mock.h"


TEST_SUITE_LABEL ("tpm");


/**
 * Helper function to setup the TPM for testing.
 *
 * @param test The test framework
 * @param tpm The TPM instance to initialize.
 * @param flash The flash storage mock to initialize.
 */
static void setup_tpm_mock_test (CuTest *test, struct tpm *tpm, struct flash_store_mock *flash)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	int status;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;

	status = flash_store_mock_init (flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash->mock, flash->base.get_max_data_length, flash, sizeof (segment));

	status |= mock_expect (&flash->mock, flash->base.read, flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output (&flash->mock, 1, (uint8_t*) header, sizeof (segment), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (tpm, &flash->base);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release mock instances

 * @param test The test framework
 * @param tpm TPM to release
 * @param flash The flash device mock to release
 */
static void complete_tpm_mock_test (CuTest *test, struct tpm *tpm, struct flash_store_mock *flash)
{
	int status;

	status = flash_store_mock_validate_and_release (flash);
	CuAssertIntEquals (test, 0, status);

	tpm_release (tpm);
}

/*******************
 * Test cases
 *******************/

static void tpm_test_init (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, tpm.observer.on_soft_reset);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_large_flash_blocks (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash,
		sizeof (segment) * 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_no_header (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_no_header_no_data (CuTest *test)
{
	uint8_t segment[512];
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	memset (segment, 0xff, sizeof (segment));

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_NO_DATA, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	memset (segment, 0, sizeof (segment));
	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_no_header_corrupt_data (CuTest *test)
{
	uint8_t segment[512];
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	memset (segment, 0xff, sizeof (segment));

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_CORRUPT_DATA,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	memset (segment, 0, sizeof (segment));
	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;

	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear (CuTest *test)
{
	uint8_t segment[512] = {0};
	uint8_t empty_buffer[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int id;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash, 3);

	memset (empty_buffer, 0xff, sizeof (empty_buffer));
	for (id = 2; id > 0; id--) {
		status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (id),
			MOCK_ARG_PTR_CONTAINS (empty_buffer, sizeof (empty_buffer)), MOCK_ARG (sizeof (empty_buffer)));
	}

	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (NULL, &flash.base);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	status = tpm_init (&tpm, NULL);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_small_flash_blocks (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, 512 - 1);

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, TPM_INSUFFICIENT_STORAGE, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_block_size_fail (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash,
		FLASH_STORE_GET_MAX_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, FLASH_STORE_GET_MAX_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_read_header_fail (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, 512);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_READ_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (512));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, FLASH_STORE_READ_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_no_header_write_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	header->magic = TPM_MAGIC;

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)),
		MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear_write_empty_buffer_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	uint8_t empty_buffer[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int id;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash, 3);

	memset (empty_buffer, 0xff, sizeof (empty_buffer));
	for (id = 2; id > 0; id--) {
		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
			MOCK_ARG (id), MOCK_ARG_PTR_CONTAINS (empty_buffer, sizeof (empty_buffer)),
			MOCK_ARG (sizeof (empty_buffer)));
	}

	CuAssertIntEquals (test, 0, status);

	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear_write_header_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	uint8_t empty_buffer[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int id;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash, 3);

	memset (empty_buffer, 0xff, sizeof (empty_buffer));
	for (id = 2; id > 0; id--) {
		status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (id),
			MOCK_ARG_PTR_CONTAINS (empty_buffer, sizeof (empty_buffer)), MOCK_ARG (sizeof (empty_buffer)));
	}

	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)),
		MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear_write_empty_buffer_and_header_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	uint8_t empty_buffer[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int id;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash, 3);

	memset (empty_buffer, 0xff, sizeof (empty_buffer));
	for (id = 2; id > 0; id--) {
		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_BAD_DATA_LENGTH,
			MOCK_ARG (id), MOCK_ARG_PTR_CONTAINS (empty_buffer, sizeof (empty_buffer)),
			MOCK_ARG (sizeof (empty_buffer)));
	}

	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)),
		MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear_num_blocks_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	status = flash_store_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_max_data_length, &flash, sizeof (segment));

	status |= mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, (uint8_t*) header, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash,
		FLASH_STORE_NUM_BLOCKS_FAILED);

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base);
	CuAssertIntEquals (test, FLASH_STORE_NUM_BLOCKS_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_release_null (CuTest *test)
{
	TEST_START;

	tpm_release (NULL);
}

static void tpm_test_get_counter (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->nv_counter = 0xAA;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output (&flash.mock, 1, segment, sizeof (segment), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_counter (&tpm, &counter);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xAA, counter);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_counter_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_get_counter (NULL, &counter);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	status = tpm_get_counter (&tpm, NULL);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_counter_invalid_storage (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->nv_counter = 0xAA;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output (&flash.mock, 1, segment, sizeof (segment), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_counter (&tpm, &counter);
	CuAssertIntEquals (test, TPM_INVALID_STORAGE, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_counter_invalid_storage_no_data (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_NO_DATA, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (512));

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_counter (&tpm, &counter);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_counter_invalid_storage_corrupt_data (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_CORRUPT_DATA,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (512));

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_counter (&tpm, &counter);
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_counter_read_fail (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_READ_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (512));

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_counter (&tpm, &counter);
	CuAssertIntEquals (test, FLASH_STORE_READ_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->nv_counter = 1;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_invalid_storage (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->nv_counter = 3;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	header->nv_counter = 1;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_invalid_storage_no_data (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->nv_counter = 3;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_NO_DATA, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	header->nv_counter = 1;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_invalid_storage_corrupt_data (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->nv_counter = 3;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_CORRUPT_DATA,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	header->nv_counter = 1;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_increment_counter (NULL);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_read_fail (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_READ_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (512));

	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, FLASH_STORE_READ_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_write_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->nv_counter = 1;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)),
		MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t storage[512];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (storage); i++) {
		storage[i] = i;
	}

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (1),
		MOCK_ARG_PTR_CONTAINS (storage, sizeof (storage)), MOCK_ARG (sizeof (storage)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 0, storage, sizeof (storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_not_first (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t storage[512];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (storage); i++) {
		storage[i] = i;
	}

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (15),
		MOCK_ARG_PTR_CONTAINS (storage, sizeof (storage)), MOCK_ARG (sizeof (storage)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 14, storage, sizeof (storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t storage[512];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_set_storage (NULL, 0, storage, sizeof (storage));
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_write_fail (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t storage[512];
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (storage); i++) {
		storage[i] = i;
	}

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (1), MOCK_ARG_PTR_CONTAINS (storage, sizeof (storage)),
		MOCK_ARG (sizeof (storage)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 0, storage, sizeof (storage));
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t exp_storage[512];
	uint8_t storage[sizeof (exp_storage)] = {0};
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (exp_storage); i++) {
		exp_storage[i] = i;
	}

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (exp_storage), MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (exp_storage)));
	status |= mock_expect_output (&flash.mock, 1, exp_storage, sizeof (exp_storage), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage), false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_storage, storage, sizeof (exp_storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_mask_errors (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t exp_storage[512];
	uint8_t storage[sizeof (exp_storage)] = {0};
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (exp_storage); i++) {
		exp_storage[i] = i;
	}

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (exp_storage), MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (exp_storage)));
	status |= mock_expect_output (&flash.mock, 1, exp_storage, sizeof (exp_storage), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage), true);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_storage, storage, sizeof (exp_storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_not_first (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t exp_storage[512];
	uint8_t storage[sizeof (exp_storage)] = {0};
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (exp_storage); i++) {
		exp_storage[i] = i;
	}

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (exp_storage), MOCK_ARG (11),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (exp_storage)));
	status |= mock_expect_output (&flash.mock, 1, exp_storage, sizeof (exp_storage), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 10, storage, sizeof (storage), false);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_storage, storage, sizeof (exp_storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_no_data (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t storage[512] = {0};
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_NO_DATA, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (storage)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage), false);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_no_data_mask_errors (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t exp_storage[512];
	uint8_t storage[sizeof (exp_storage)] = {0};
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (exp_storage); i++) {
		exp_storage[i] = i;
	}

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_NO_DATA, MOCK_ARG (1),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (exp_storage)));
	status |= mock_expect_output (&flash.mock, 1, exp_storage, sizeof (exp_storage), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage), true);
	CuAssertIntEquals (test, 0, status);

	memset (exp_storage, 0xff, sizeof (exp_storage));
	status = testing_validate_array (exp_storage, storage, sizeof (exp_storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_corrupt_data (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t storage[512] = {0};
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_CORRUPT_DATA,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (storage)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage), false);
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_corrupt_data_mask_errors (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t exp_storage[512];
	uint8_t storage[sizeof (exp_storage)] = {0};
	int status;
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (exp_storage); i++) {
		exp_storage[i] = i;
	}

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_CORRUPT_DATA,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (exp_storage)));
	status |= mock_expect_output (&flash.mock, 1, exp_storage, sizeof (exp_storage), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage), true);
	CuAssertIntEquals (test, 0, status);

	memset (exp_storage, 0xff, sizeof (exp_storage));
	status = testing_validate_array (exp_storage, storage, sizeof (exp_storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t storage[512] = {0};
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_get_storage (NULL, 0, storage, sizeof (storage), false);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_read_storage_fail (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	uint8_t storage[512] = {0};
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_READ_FAILED,
		MOCK_ARG (1), MOCK_ARG_NOT_NULL, MOCK_ARG (512));

	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage), false);
	CuAssertIntEquals (test, FLASH_STORE_READ_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset (CuTest *test)
{
	uint8_t segment[512] = {0};
	uint8_t empty_buffer[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int id;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash, 3);

	memset (empty_buffer, 0xff, sizeof (empty_buffer));
	for (id = 2; id > 0; id--) {
		status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (id),
			MOCK_ARG_PTR_CONTAINS (empty_buffer, sizeof (empty_buffer)), MOCK_ARG (sizeof (empty_buffer)));
	}

	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_not_scheduled (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 0;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_invalid_storage (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_invalid_storage_no_data (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_NO_DATA, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_invalid_storage_corrupt_data (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_CORRUPT_DATA,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	tpm.observer.on_soft_reset (NULL);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_read_fail (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_READ_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (512));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_write_empty_buffer_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	uint8_t empty_buffer[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int id;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash, 3);

	memset (empty_buffer, 0xff, sizeof (empty_buffer));
	for (id = 2; id > 0; id--) {
		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
			MOCK_ARG (id), MOCK_ARG_PTR_CONTAINS (empty_buffer, sizeof (empty_buffer)),
			MOCK_ARG (sizeof (empty_buffer)));
	}

	CuAssertIntEquals (test, 0, status);

	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_write_header_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	uint8_t empty_buffer[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int id;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash, 3);

	memset (empty_buffer, 0xff, sizeof (empty_buffer));
	for (id = 2; id > 0; id--) {
		status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (id),
			MOCK_ARG_PTR_CONTAINS (empty_buffer, sizeof (empty_buffer)), MOCK_ARG (sizeof (empty_buffer)));
	}

	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)),
		MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_write_empty_buffer_and_header_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	uint8_t empty_buffer[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int id;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash, 3);

	memset (empty_buffer, 0xff, sizeof (empty_buffer));
	for (id = 2; id > 0; id--) {
		status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_BAD_DATA_LENGTH,
			MOCK_ARG (id), MOCK_ARG_PTR_CONTAINS (empty_buffer, sizeof (empty_buffer)),
			MOCK_ARG (sizeof (empty_buffer)));
	}

	header->clear = 0;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)),
		MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_num_blocks_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	status |= mock_expect (&flash.mock, flash.base.get_num_blocks, &flash,
		FLASH_STORE_NUM_BLOCKS_FAILED);

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 0;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->clear = 1;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_already_scheduled (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_invalid_storage (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_invalid_storage_no_data (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_NO_DATA, MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_invalid_storage_corrupt_data (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC ^ 0x55;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_CORRUPT_DATA,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->magic = TPM_MAGIC;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 0, MOCK_ARG (0),
		MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)), MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_null (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_schedule_clear (NULL);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_read_fail (CuTest *test)
{
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_STORE_READ_FAILED,
		MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (512));

	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, FLASH_STORE_READ_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_write_fail (CuTest *test)
{
	uint8_t segment[512] = {0};
	struct tpm_header *header = (struct tpm_header*) segment;
	struct flash_store_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header->magic = TPM_MAGIC;
	header->format_id = TPM_HEADER_FORMAT;
	header->clear = 0;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, sizeof (segment), MOCK_ARG (0),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (segment)));
	status |= mock_expect_output_tmp (&flash.mock, 1, segment, sizeof (segment), 2);

	header->clear = 1;
	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_STORE_WRITE_FAILED,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (segment, sizeof (segment)),
		MOCK_ARG (sizeof (segment)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, FLASH_STORE_WRITE_FAILED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}


TEST_SUITE_START (tpm);

TEST (tpm_test_init);
TEST (tpm_test_init_large_flash_blocks);
TEST (tpm_test_init_no_header);
TEST (tpm_test_init_no_header_no_data);
TEST (tpm_test_init_no_header_corrupt_data);
TEST (tpm_test_init_clear);
TEST (tpm_test_init_null);
TEST (tpm_test_init_small_flash_blocks);
TEST (tpm_test_init_block_size_fail);
TEST (tpm_test_init_read_header_fail);
TEST (tpm_test_init_no_header_write_fail);
TEST (tpm_test_init_clear_write_empty_buffer_fail);
TEST (tpm_test_init_clear_write_header_fail);
TEST (tpm_test_init_clear_write_empty_buffer_and_header_fail);
TEST (tpm_test_init_clear_num_blocks_fail);
TEST (tpm_test_release_null);
TEST (tpm_test_get_counter);
TEST (tpm_test_get_counter_null);
TEST (tpm_test_get_counter_invalid_storage);
TEST (tpm_test_get_counter_invalid_storage_no_data);
TEST (tpm_test_get_counter_invalid_storage_corrupt_data);
TEST (tpm_test_get_counter_read_fail);
TEST (tpm_test_increment_counter);
TEST (tpm_test_increment_counter_invalid_storage);
TEST (tpm_test_increment_counter_invalid_storage_no_data);
TEST (tpm_test_increment_counter_invalid_storage_corrupt_data);
TEST (tpm_test_increment_counter_null);
TEST (tpm_test_increment_counter_read_fail);
TEST (tpm_test_increment_counter_write_fail);
TEST (tpm_test_set_storage);
TEST (tpm_test_set_storage_not_first);
TEST (tpm_test_set_storage_null);
TEST (tpm_test_set_storage_write_fail);
TEST (tpm_test_get_storage);
TEST (tpm_test_get_storage_mask_errors);
TEST (tpm_test_get_storage_not_first);
TEST (tpm_test_get_storage_no_data);
TEST (tpm_test_get_storage_no_data_mask_errors);
TEST (tpm_test_get_storage_corrupt_data);
TEST (tpm_test_get_storage_corrupt_data_mask_errors);
TEST (tpm_test_get_storage_null);
TEST (tpm_test_get_storage_read_storage_fail);
TEST (tpm_test_on_soft_reset);
TEST (tpm_test_on_soft_reset_not_scheduled);
TEST (tpm_test_on_soft_reset_invalid_storage);
TEST (tpm_test_on_soft_reset_invalid_storage_no_data);
TEST (tpm_test_on_soft_reset_invalid_storage_corrupt_data);
TEST (tpm_test_on_soft_reset_null);
TEST (tpm_test_on_soft_reset_read_fail);
TEST (tpm_test_on_soft_reset_write_empty_buffer_fail);
TEST (tpm_test_on_soft_reset_write_header_fail);
TEST (tpm_test_on_soft_reset_write_empty_buffer_and_header_fail);
TEST (tpm_test_on_soft_reset_num_blocks_fail);
TEST (tpm_test_schedule_clear);
TEST (tpm_test_schedule_clear_already_scheduled);
TEST (tpm_test_schedule_clear_invalid_storage);
TEST (tpm_test_schedule_clear_invalid_storage_no_data);
TEST (tpm_test_schedule_clear_invalid_storage_corrupt_data);
TEST (tpm_test_schedule_clear_null);
TEST (tpm_test_schedule_clear_read_fail);
TEST (tpm_test_schedule_clear_write_fail);

TEST_SUITE_END;
