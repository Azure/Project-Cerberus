// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_updater.h"
#include "testing/mock/flash/flash_mock.h"


TEST_SUITE_LABEL ("flash_updater");


/*******************
 * Test cases
 *******************/

static void flash_updater_test_init (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_init_not_block_aligned (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10001, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (NULL, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);

	status = flash_updater_init (&updater, NULL, 0x10000, 0x10000);
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_init_sector (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init_sector (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_init_sector_not_sector_aligned (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init_sector (&updater, &flash.base, 0x10001, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_init_sector_null (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init_sector (NULL, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);

	status = flash_updater_init_sector (&updater, NULL, 0x10000, 0x10000);
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_release_null (CuTest *test)
{
	TEST_START;

	flash_updater_release (NULL);
}

static void flash_updater_test_prepare_for_update (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 5, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_sector (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init_sector (&updater, &flash.base, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&flash, 0x20000, 10);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 10);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 10, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_not_aligned (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10010, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10010, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 5, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x20);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10020, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 5, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_null (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (NULL, 5);
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 0x10001);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 5);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_all (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update_erase_all (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 5, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_all_sector (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init_sector (&updater, &flash.base, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&flash, 0x20000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update_erase_all (&updater, 10);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 10, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_all_not_aligned (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10010, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10010, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update_erase_all (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 5, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_all_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x50);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10050, 0xffb0);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update_erase_all (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 5, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_all_zero_length (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update_erase_all (&updater, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_all_null (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update_erase_all (NULL, 5);
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_all_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update_erase_all (&updater, 0x10001);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_prepare_for_update_erase_all_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update_erase_all (&updater, 5);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) -sizeof (data), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_multiple (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10004), MOCK_ARG_PTR_CONTAINS (data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10009), MOCK_ARG_PTR_CONTAINS (data3, sizeof (data3)),
		MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1), status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data2), status);

	status = flash_updater_write_update_data (&updater, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data2) + sizeof (data3), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) (-sizeof (data1) - sizeof (data2) - sizeof (data3)), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_region_end (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x1fffc),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	/* Force the write offset to the end of the region. */
	updater.write_offset = 0xfffc;

	status = flash_updater_write_update_data (&updater, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x30);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10030),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) -sizeof (data), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_null (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (NULL, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);

	status = flash_updater_write_update_data (&updater, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_write_error (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_write_after_error (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_WRITE_FAILED,
		MOCK_ARG (0x10004), MOCK_ARG_PTR_CONTAINS (data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10004), MOCK_ARG_PTR_CONTAINS (data3, sizeof (data3)),
		MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1), status);

	status = flash_updater_write_update_data (&updater, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data3), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) (-sizeof (data1) - sizeof (data3)), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_partial_write (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, 2, MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 2, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, -2, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_write_after_partial_write (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, 2, MOCK_ARG (0x10004),
		MOCK_ARG_PTR_CONTAINS (data2, sizeof (data2)), MOCK_ARG (sizeof (data2)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10006), MOCK_ARG_PTR_CONTAINS (data3, sizeof (data3)),
		MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_UPDATER_INCOMPLETE_WRITE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + 2, status);

	status = flash_updater_write_update_data (&updater, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + 2 + sizeof (data3), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) (-sizeof (data1) - 2 - sizeof (data3)), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_region_full (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) -sizeof (data1), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_region_full_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, sizeof (data1) + 0x10);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x10);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10010),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) -sizeof (data1), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_too_long (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, sizeof (data1) + 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) -sizeof (data1), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_too_long_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, sizeof (data1) + 1 + 0x10);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x10);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10010),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, FLASH_UPDATER_OUT_OF_SPACE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, (int) -sizeof (data1), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_restart_write (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10004), MOCK_ARG_PTR_CONTAINS (data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= flash_mock_expect_erase_flash_verify (&flash, 0x10000, 10);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data3, sizeof (data3)),
		MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data2), status);

	status = flash_updater_prepare_for_update (&updater, 10);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data3), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 10 - sizeof (data3), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_restart_write_erase_all (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10004), MOCK_ARG_PTR_CONTAINS (data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= flash_mock_expect_erase_flash_verify (&flash, 0x10000, 0x10000);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data3, sizeof (data3)),
		MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data2), status);

	status = flash_updater_prepare_for_update_erase_all (&updater, 10);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data3), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 10 - sizeof (data3), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_restart_write_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x40);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1), MOCK_ARG (0x10040),
		MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)), MOCK_ARG (sizeof (data1)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10044), MOCK_ARG_PTR_CONTAINS (data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= flash_mock_expect_erase_flash_verify (&flash, 0x10040, 10);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10040), MOCK_ARG_PTR_CONTAINS (data3, sizeof (data3)),
		MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data2), status);

	status = flash_updater_prepare_for_update (&updater, 10);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data3), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 10 - sizeof (data3), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_write_update_data_restart_write_erase_error (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data1[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t data2[] = {0x05, 0x06, 0x07, 0x08, 0x09};
	uint8_t data3[] = {0x0a, 0x0b, 0x0c};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, 10);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data1),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data1, sizeof (data1)),
		MOCK_ARG (sizeof (data1)));
	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data2),
		MOCK_ARG (0x10004), MOCK_ARG_PTR_CONTAINS (data2, sizeof (data2)),
		MOCK_ARG (sizeof (data2)));

	status |= mock_expect (&flash.mock, flash.base.get_block_size, &flash, FLASH_BLOCK_SIZE_FAILED,
		MOCK_ARG_NOT_NULL);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data3),
		MOCK_ARG (0x10009), MOCK_ARG_PTR_CONTAINS (data3, sizeof (data3)),
		MOCK_ARG (sizeof (data3)));

	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 10);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data1, sizeof (data1));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data2, sizeof (data2));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data2), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 10 - sizeof (data1) - sizeof (data2), status);

	status = flash_updater_prepare_for_update (&updater, 5);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE_FAILED, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data2), status);

	status = flash_updater_write_update_data (&updater, data3, sizeof (data3));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, sizeof (data1) + sizeof (data2) + sizeof (data3), status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 10 - (int) (sizeof (data1) + sizeof (data2) + sizeof (data3)), status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_get_remaining_bytes_null (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_verify (&flash, 0x10000, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_prepare_for_update (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_get_bytes_written_null (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;
	uint8_t data[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.write, &flash, sizeof (data), MOCK_ARG (0x10000),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_write_update_data (&updater, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_apply_update_offset_null (CuTest *test)
{
	TEST_START;

	flash_updater_apply_update_offset (NULL, 0x20);
}

static void flash_updater_test_check_update_size (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_check_update_size (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_check_update_size_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x50);

	status = flash_updater_check_update_size (&updater, 5);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_check_update_size_max_size (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_check_update_size (&updater, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_check_update_size_max_size_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x50);

	status = flash_updater_check_update_size (&updater, 0xffb0);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_check_update_size_null (CuTest *test)
{
	int status;

	TEST_START;

	status = flash_updater_check_update_size (NULL, 5);
	CuAssertIntEquals (test, FLASH_UPDATER_INVALID_ARGUMENT, status);
}

static void flash_updater_test_check_update_size_too_large (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_check_update_size (&updater, 0x10001);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}

static void flash_updater_test_check_update_size_too_large_with_offset (CuTest *test)
{
	struct flash_mock flash;
	struct flash_updater updater;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_init (&updater, &flash.base, 0x10000, 0x10000);
	CuAssertIntEquals (test, 0, status);

	flash_updater_apply_update_offset (&updater, 0x50);

	status = flash_updater_check_update_size (&updater, 0xffb1);
	CuAssertIntEquals (test, FLASH_UPDATER_TOO_LARGE, status);

	status = flash_updater_get_bytes_written (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_updater_get_remaining_bytes (&updater);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	flash_updater_release (&updater);
}


TEST_SUITE_START (flash_updater);

TEST (flash_updater_test_init);
TEST (flash_updater_test_init_not_block_aligned);
TEST (flash_updater_test_init_null);
TEST (flash_updater_test_init_sector);
TEST (flash_updater_test_init_sector_not_sector_aligned);
TEST (flash_updater_test_init_sector_null);
TEST (flash_updater_test_release_null);
TEST (flash_updater_test_prepare_for_update);
TEST (flash_updater_test_prepare_for_update_sector);
TEST (flash_updater_test_prepare_for_update_not_aligned);
TEST (flash_updater_test_prepare_for_update_with_offset);
TEST (flash_updater_test_prepare_for_update_zero_length);
TEST (flash_updater_test_prepare_for_update_null);
TEST (flash_updater_test_prepare_for_update_too_large);
TEST (flash_updater_test_prepare_for_update_erase_error);
TEST (flash_updater_test_prepare_for_update_erase_all);
TEST (flash_updater_test_prepare_for_update_erase_all_sector);
TEST (flash_updater_test_prepare_for_update_erase_all_not_aligned);
TEST (flash_updater_test_prepare_for_update_erase_all_with_offset);
TEST (flash_updater_test_prepare_for_update_erase_all_zero_length);
TEST (flash_updater_test_prepare_for_update_erase_all_null);
TEST (flash_updater_test_prepare_for_update_erase_all_too_large);
TEST (flash_updater_test_prepare_for_update_erase_all_erase_error);
TEST (flash_updater_test_write_update_data);
TEST (flash_updater_test_write_update_data_multiple);
TEST (flash_updater_test_write_update_data_region_end);
TEST (flash_updater_test_write_update_data_with_offset);
TEST (flash_updater_test_write_update_data_null);
TEST (flash_updater_test_write_update_data_write_error);
TEST (flash_updater_test_write_update_data_write_after_error);
TEST (flash_updater_test_write_update_data_partial_write);
TEST (flash_updater_test_write_update_data_write_after_partial_write);
TEST (flash_updater_test_write_update_data_region_full);
TEST (flash_updater_test_write_update_data_region_full_with_offset);
TEST (flash_updater_test_write_update_data_too_long);
TEST (flash_updater_test_write_update_data_too_long_with_offset);
TEST (flash_updater_test_write_update_data_restart_write);
TEST (flash_updater_test_write_update_data_restart_write_erase_all);
TEST (flash_updater_test_write_update_data_restart_write_with_offset);
TEST (flash_updater_test_write_update_data_restart_write_erase_error);
TEST (flash_updater_test_get_remaining_bytes_null);
TEST (flash_updater_test_get_bytes_written_null);
TEST (flash_updater_test_apply_update_offset_null);
TEST (flash_updater_test_check_update_size);
TEST (flash_updater_test_check_update_size_with_offset);
TEST (flash_updater_test_check_update_size_max_size);
TEST (flash_updater_test_check_update_size_max_size_with_offset);
TEST (flash_updater_test_check_update_size_null);
TEST (flash_updater_test_check_update_size_too_large);
TEST (flash_updater_test_check_update_size_too_large_with_offset);

TEST_SUITE_END;
