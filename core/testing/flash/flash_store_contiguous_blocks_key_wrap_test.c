// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_store_contiguous_blocks_key_wrap.h"
#include "flash/flash_store_contiguous_blocks_key_wrap_static.h"
#include "testing/mock/crypto/aes_key_wrap_mock.h"
#include "testing/mock/flash/flash_mock.h"


TEST_SUITE_LABEL ("flash_store_contiguous_blocks_key_wrap");


/**
 * Dependencies for testing flash block storage using AES key wrapping.
 */
struct flash_store_contiguous_blocks_key_wrap_testing {
	struct flash_mock flash;							/**< The flash device. */
	struct aes_key_wrap_mock key_wrap;					/**< AES key wrap for data encryption. */
	uint32_t page;										/**< Number of bytes per flash programming page. */
	uint32_t sector;									/**< Number of bytes per flash erase sector. */
	uint32_t bytes;										/**< Total storage for the flash flash device. */
	uint32_t min_write;									/**< Minimum number of page programming bytes. */
	struct flash_store_contiguous_blocks_state state;	/**< Flash storage state. */
	struct flash_store_contiguous_blocks_key_wrap test;	/**< Flash storage under test. */
};


/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param store Testing dependencies to initialize.
 */
static void flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (CuTest *test,
	struct flash_store_contiguous_blocks_key_wrap_testing *store)
{
	int status;

	status = flash_mock_init (&store->flash);
	CuAssertIntEquals (test, 0, status);

	status = aes_key_wrap_mock_init (&store->key_wrap);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param store Testing dependencies to release.
 */
static void flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (CuTest *test,
	struct flash_store_contiguous_blocks_key_wrap_testing *store)
{
	int status;

	status = flash_mock_validate_and_release (&store->flash);
	status |= aes_key_wrap_mock_validate_and_release (&store->key_wrap);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to set up dependencies and expectations for flash store initialization.
 *
 * @param test The test framework.
 * @param store Testing dependencies that will be initialized.
 * @param page Number of bytes per programming page.
 * @param sector Number of bytes per erase sector.
 * @param bytes Total size of the flash device.
 * @param min_write Minimum number of bytes required to write to a page.
 */
static void flash_store_contiguous_blocks_key_wrap_testing_prepare_init (CuTest *test,
	struct flash_store_contiguous_blocks_key_wrap_testing *store, uint32_t page, uint32_t sector,
	uint32_t bytes, uint32_t min_write)
{
	int status;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, store);

	store->page = page;
	store->sector = sector;
	store->bytes = bytes;
	store->min_write = min_write;

	status = mock_expect (&store->flash.mock, store->flash.base.get_sector_size, &store->flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store->flash.mock, 0, &store->sector, sizeof (store->sector),
		-1);

	status |= mock_expect (&store->flash.mock, store->flash.base.get_device_size, &store->flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store->flash.mock, 0, &store->bytes, sizeof (store->bytes), -1);

	status |= mock_expect (&store->flash.mock, store->flash.base.get_page_size, &store->flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store->flash.mock, 0, &store->page, sizeof (store->page), -1);

	status |= mock_expect (&store->flash.mock, store->flash.base.minimum_write_per_page,
		&store->flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store->flash.mock, 0, &store->min_write,
		sizeof (store->min_write), -1);

	CuAssertIntEquals (test, 0, status);
}

/**
 * Release test components and validate all mocks.
 *
 * @param test The test framework.
 * @param store Testing dependencies to release.
 */
static void flash_store_contiguous_blocks_key_wrap_testing_release (CuTest *test,
	struct flash_store_contiguous_blocks_key_wrap_testing *store)
{
	flash_store_contiguous_blocks_key_wrap_release (&store->test);
	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, store);
}


/*******************
 * Test cases
 *******************/

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.base.base.write);
	CuAssertPtrNotNull (test, store.test.base.base.read);
	CuAssertPtrNotNull (test, store.test.base.base.erase);
	CuAssertPtrNotNull (test, store.test.base.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.base.get_num_blocks);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_one_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xfd000, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_one_sector_per_block_max_space_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xfd000, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_multiple_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xff400, 3, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_multiple_sector_per_block_max_space_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xff400, 3, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_data_not_sector_aligned_max_space (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xffa00, 3, 384, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 384, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_extra_sector_for_iv_max_space (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xffa00, 3, sector, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, sector, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_extra_sector_for_iv_with_padding_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xffa00, 3, (sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, (sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_max_data (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, (64 * 1024) - 1, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, (64 * 1024) - 1, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 0x11000, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (NULL, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, NULL,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		NULL, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_no_data (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 0, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_block_too_large (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xfe000, 3, 64 * 1024, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_sector_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_not_sector_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10100, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_device_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_base_out_of_range (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, bytes, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_one_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xfe000, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_one_sector_per_block_not_key_wrap_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xfe000, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 7,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_multiple_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xff500, 3, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_multiple_sector_per_block_not_key_wrap_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xff500, 3, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 7,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_data_not_sector_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xffb00, 3, 384, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_extra_sector_for_iv_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xffb00, 3, sector, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_extra_sector_for_iv_with_padding_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0xffb00, 3, (sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_page_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_min_write_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		FLASH_MINIMUM_WRITE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.base.base.write);
	CuAssertPtrNotNull (test, store.test.base.base.read);
	CuAssertPtrNotNull (test, store.test.base.base.erase);
	CuAssertPtrNotNull (test, store.test.base.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.base.get_num_blocks);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_one_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x2000, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_one_sector_per_block_max_space_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x2000, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_multiple_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x800, 3, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_multiple_sector_per_block_max_space_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x800, 3, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_data_not_sector_aligned_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x400, 3, 384, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 384, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_extra_sector_for_iv_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x400, 3, sector, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, sector, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_extra_sector_for_iv_with_padding_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x400, 3, (sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, (sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_max_data (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0xf0000, 3, (64 * 1024) - 1, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, (64 * 1024) - 1, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 0x11000, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (NULL,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		NULL, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, NULL, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_no_data (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 0, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_block_too_large (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0xfe000, 3, 64 * 1024, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_sector_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_not_sector_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10100, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_device_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_base_out_of_range (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, bytes, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_one_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x1000, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_one_sector_per_block_not_key_wrap_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x1000, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 5,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_multiple_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x700, 3, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_multiple_sector_per_block_not_key_wrap_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x700, 3, 1024 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 5,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_data_not_sector_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x300, 3, 384, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_extra_sector_for_iv_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x300, 3, sector, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_extra_sector_for_iv_with_padding_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x300, 3, (sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_page_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_min_write_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		FLASH_MINIMUM_WRITE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.base.base.write);
	CuAssertPtrNotNull (test, store.test.base.base.read);
	CuAssertPtrNotNull (test, store.test.base.base.erase);
	CuAssertPtrNotNull (test, store.test.base.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.base.get_num_blocks);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_one_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xfd000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_multiple_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xff400, 3,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_multiple_sector_per_block_max_space_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xff400, 3,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_data_not_sector_aligned_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xffa00, 3, 384, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(sector * 2) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_iv_max_space (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xffa00, 3,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)),
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(sector * 2) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_iv_with_padding_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xffa00, 3,
		(sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
			AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(sector * 2) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_header_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xffa00, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(sector * 2) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_max_data (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3,
		(64 * 1024) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(64 * 1024) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (NULL, &store.state,
		&store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test, NULL,
		&store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, NULL, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_no_data (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 0, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_block_too_large (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xfe000, 3, 64 * 1024, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_sector_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_not_sector_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10100, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_device_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_base_out_of_range (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, bytes, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_one_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xfe000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_multiple_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xff500, 3,
		1024 - sizeof (struct flash_store_header) - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_multiple_sector_per_block_not_key_wrap_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xff500, 3,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 3, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_data_not_sector_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xffb00, 3, 384, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_iv_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xffb00, 3,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)),
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_iv_with_padding_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xffb00, 3,
		(sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
			AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_header_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0xffb00, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_block_too_large (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3,
		((64 * 1024) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
			AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_page_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_min_write_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		FLASH_MINIMUM_WRITE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.base.base.write);
	CuAssertPtrNotNull (test, store.test.base.base.read);
	CuAssertPtrNotNull (test, store.test.base.base.erase);
	CuAssertPtrNotNull (test, store.test.base.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.base.get_num_blocks);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_one_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x2000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_multiple_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x800, 3,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_multiple_sector_per_block_max_space_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x800, 3,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 1, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_data_not_sector_aligned_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x400, 3, 384, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(sector * 2) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_iv_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x400, 3,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)),
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(sector * 2) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_iv_with_padding_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x400, 3,
		(sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
			AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(sector * 2) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_header_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x400, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(sector * 2) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_max_data (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0xf0000, 3,
		(64 * 1024) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		(64 * 1024) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (NULL,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		NULL, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, NULL, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_no_data (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 0, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_block_too_large (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0xfe000, 3, 64 * 1024, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_sector_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_not_sector_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10100, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_device_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_base_out_of_range (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, bytes, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_one_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x1000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_multiple_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x700, 3,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_multiple_sector_per_block_not_key_wrap_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x700, 3,
		1024 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE - 4, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_data_not_sector_aligned_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x300, 3, 384, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_iv_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x300, 3,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)),
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_iv_with_padding_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x300, 3,
		(sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
			AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_header_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x300, 3, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_block_too_large
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0xf0000, 3,
		((64 * 1024) - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
			AES_KEY_WRAP_INTERFACE_BLOCK_SIZE) + 1, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_page_size_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_min_write_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		FLASH_MINIMUM_WRITE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 0, &store.key_wrap.base);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	CuAssertPtrNotNull (test, store.test.base.base.write);
	CuAssertPtrNotNull (test, store.test.base.base.read);
	CuAssertPtrNotNull (test, store.test.base.base.erase);
	CuAssertPtrNotNull (test, store.test.base.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.base.get_num_blocks);

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_one_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state,
			&store.flash.base, 0xfb000, 5, &store.key_wrap.base)
	};
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test,
		sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 5 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 5, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;

	struct flash_store_contiguous_blocks_key_wrap null_state =
		flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (NULL, &store.flash.base,
		0x10000, 3, &store.key_wrap.base);

	struct flash_store_contiguous_blocks_key_wrap null_flash =
		flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state, NULL,
		0x10000, 3, &store.key_wrap.base);

	struct flash_store_contiguous_blocks_key_wrap null_key_wrap =
		flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state,
		&store.flash.base, 0x10000, 3, NULL);
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_state (NULL, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_state, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_flash, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_key_wrap, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_one_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state,
			&store.flash.base, 0xfc000, 5, &store.key_wrap.base)
	};
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test,
		sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	CuAssertPtrNotNull (test, store.test.base.base.write);
	CuAssertPtrNotNull (test, store.test.base.base.read);
	CuAssertPtrNotNull (test, store.test.base.base.erase);
	CuAssertPtrNotNull (test, store.test.base.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.base.get_num_blocks);

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_decreasing_one_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (
			&store.state, &store.flash.base, 0x3000, 4, &store.key_wrap.base)
	};
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test,
		sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test, sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 4 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 4, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_decreasing_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;

	struct flash_store_contiguous_blocks_key_wrap null_state =
		flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (NULL,
		&store.flash.base, 0x10000, 3, &store.key_wrap.base);

	struct flash_store_contiguous_blocks_key_wrap null_flash =
		flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (&store.state,
		NULL, 0x10000, 3, &store.key_wrap.base);

	struct flash_store_contiguous_blocks_key_wrap null_key_wrap =
		flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (&store.state,
		&store.flash.base, 0x10000, 3, NULL);
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_state (NULL, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_state, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_flash, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_key_wrap, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_decreasing_one_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (
			&store.state, &store.flash.base, 0x2000, 4, &store.key_wrap.base)
	};
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test,
		sector - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	CuAssertPtrNotNull (test, store.test.base.base.write);
	CuAssertPtrNotNull (test, store.test.base.base.read);
	CuAssertPtrNotNull (test, store.test.base.base.erase);
	CuAssertPtrNotNull (test, store.test.base.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.base.get_num_blocks);

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_one_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state,
			&store.flash.base, 0xfc000, 4, &store.key_wrap.base)
	};
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 4 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 4, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;

	struct flash_store_contiguous_blocks_key_wrap null_state =
		flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (NULL,
		&store.flash.base, 0x10000, 3, &store.key_wrap.base);

	struct flash_store_contiguous_blocks_key_wrap null_flash =
		flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state, NULL,
		0x10000, 3, &store.key_wrap.base);

	struct flash_store_contiguous_blocks_key_wrap null_key_wrap =
		flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state,
		&store.flash.base, 0x10000, 3, NULL);
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_state (NULL, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_state, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_flash, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_key_wrap, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_one_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state,
			&store.flash.base, 0xfd000, 4, &store.key_wrap.base)
	};
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 0);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	CuAssertPtrNotNull (test, store.test.base.base.write);
	CuAssertPtrNotNull (test, store.test.base.base.read);
	CuAssertPtrNotNull (test, store.test.base.base.erase);
	CuAssertPtrNotNull (test, store.test.base.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.base.get_num_blocks);

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_decreasing_one_sector_per_block_max_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
			&store.state, &store.flash.base, 0x4000, 5, &store.key_wrap.base)
	};
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &page, sizeof (page), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.minimum_write_per_page, &store.flash,
		0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &min_write, sizeof (min_write), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (&store.test.base.base);
	CuAssertIntEquals (test,
		sector - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE, status);

	status = store.test.base.base.get_flash_size (&store.test.base.base);
	CuAssertIntEquals (test, 5 * sector, status);

	status = store.test.base.base.get_num_blocks (&store.test.base.base);
	CuAssertIntEquals (test, 5, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_decreasing_null
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;

	struct flash_store_contiguous_blocks_key_wrap null_state =
		flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (NULL,
		&store.flash.base, 0x10000, 3, &store.key_wrap.base);

	struct flash_store_contiguous_blocks_key_wrap null_flash =
		flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
		&store.state, NULL, 0x10000, 3, &store.key_wrap.base);

	struct flash_store_contiguous_blocks_key_wrap null_key_wrap =
		flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
		&store.state, &store.flash.base, 0x10000, 3, NULL);
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = flash_store_contiguous_blocks_key_wrap_init_state (NULL, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_state, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_flash, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&null_key_wrap, 256);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_decreasing_one_sector_per_block_not_enough_space
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
			&store.state, &store.flash.base, 0x3000, 5, &store.key_wrap.base)
	};
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 0);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_contiguous_blocks_key_wrap_testing_release_dependencies (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_release_null (CuTest *test)
{
	TEST_START;

	flash_store_contiguous_blocks_key_wrap_release (NULL);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_max_data_length_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_max_data_length (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_flash_size_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_flash_size (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_num_blocks_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_num_blocks (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[250];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10400, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10400), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_extra_sector_for_iv_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, page, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_pages_not_aligned_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[(page * 2) + 128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, page, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_store_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, page, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[249];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_sectors_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xfc00, sizeof (enc), sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xfc00), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_extra_sector_for_iv_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_less_than_page_size_no_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_less_than_page_size_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_larger_than_page_size_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, page, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_pages_aligned_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_pages_not_aligned_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[(page * 2) + 128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, page, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_store_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, page, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x12000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[249];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_max_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x0f};
	uint8_t data[0x1000 - (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_old_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_use_length_only_header (&store.test.base);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10400, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10400 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10400), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_extra_sector_for_header_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};
	uint8_t data[508];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_extra_sector_for_iv_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};
	uint8_t data[508];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_less_than_page_size_no_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[sizeof (enc) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_less_than_page_size_last_block_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[sizeof (enc) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_less_than_page_size_old_header_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[sizeof (enc) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_use_length_only_header (&store.test.base);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_larger_than_page_size_last_block_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x12000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_larger_than_page_size_old_header_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_use_length_only_header (&store.test.base);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_pages_aligned_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	/* The only way to enable this scenario for the AES key wrap case is to make the page size not
	 * aligned.  This forces the test case, but is not likely to happen in reality. */
	uint32_t page = 0xfe;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[512 - (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, page, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (enc) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], sizeof (enc) - write_data_len),
		MOCK_ARG (sizeof (enc) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		sizeof (enc) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_pages_not_aligned_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x02};
	uint8_t data[(page * 2) + 128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xe000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[255];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_max_length
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x0f};
	uint8_t data[0x1000 - (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_old_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_use_length_only_header (&store.test.base);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_sectors_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xfc00, sizeof (enc), sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xfc00 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xfc00), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_extra_sector_for_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_extra_sector_for_header_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};
	uint8_t data[508];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_extra_sector_for_iv_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};
	uint8_t data[508];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_less_than_page_size_no_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_less_than_page_size_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[sizeof (enc) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_less_than_page_size_last_block_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[sizeof (enc) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_less_than_page_size_old_header_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[sizeof (enc) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_use_length_only_header (&store.test.base);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_larger_than_page_size_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_larger_than_page_size_last_block_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0xe000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, write2, sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_larger_than_page_size_old_header_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_use_length_only_header (&store.test.base);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_pages_aligned_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	/* The only way to enable this scenario for the AES key wrap case is to make the page size not
	 * aligned.  This forces the test case, but is not likely to happen in reality. */
	uint32_t page = 0xfe;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[512 - (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, page, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (enc) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], sizeof (enc) - write_data_len),
		MOCK_ARG (sizeof (enc) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		sizeof (enc) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_pages_not_aligned_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x02};
	uint8_t data[(page * 2) + 128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_store_min_write
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (NULL, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.base.write (&store.test.base.base, 0, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_invalid_id (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 3, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.base.write (&store.test.base.base, -1, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_wrong_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data) - 1);
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data) + 1);
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_key_wrap_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap,
		AES_KEY_WRAP_WRAP_FAILED, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, AES_KEY_WRAP_WRAP_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_erase_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_write_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_verify_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (NULL, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.base.write (&store.test.base.base, 0, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_invalid_id (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 3, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.base.write (&store.test.base.base, -1, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_too_large (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[
		0x1000 - AES_KEY_WRAP_INTERFACE_ALIGNED_LENGTH (sizeof (struct flash_store_header)) -
		AES_KEY_WRAP_INTERFACE_BLOCK_SIZE + 1];

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_key_wrap_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap,
		AES_KEY_WRAP_WRAP_FAILED, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, AES_KEY_WRAP_WRAP_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_erase_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_write_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_verify_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_write_header_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_verify_header_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_write_old_header_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_use_length_only_header (&store.test.base);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_verify_old_header_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_use_length_only_header (&store.test.base);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_single_page_write_error
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[sizeof (enc) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_single_page_verify_error
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x00};
	uint8_t data[128];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[sizeof (enc) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_multiple_pages_write_error
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)), MOCK_ARG (sizeof (write2)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_multiple_pages_verify_error
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + page), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_multiple_pages_write_first_error
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_multiple_pages_verify_first_error
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x88, 0x01};
	uint8_t data[384];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len)];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 0x100);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.key_wrap.mock, store.key_wrap.base.wrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_AT_LEAST (sizeof (enc)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, enc, sizeof (enc), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.write (&store.test.base.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256), status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 241, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (241), status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 512, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (512), status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256), status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256), status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_decreasing_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 260, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (260), status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_decreasing_multiple_sectors
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (512), status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_decreasing_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256), status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 264, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 2);
	CuAssertIntEquals (test, 512, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_max_length
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x0f};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0xff8, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0x1f8, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_multiple_sectors_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 2);
	CuAssertIntEquals (test, 0x1f8, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_extra_sector_for_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0x200, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_extra_sector_for_header_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 2);
	CuAssertIntEquals (test, 0x200, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 508, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0x208, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_extra_sector_for_iv_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 508, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 2);
	CuAssertIntEquals (test, 0x208, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_longer_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_old_format
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_static_init
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 264, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 2);
	CuAssertIntEquals (test, 512, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_max_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x0f};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0xff8, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_multiple_sectors
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0x1f8, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_multiple_sectors_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 2);
	CuAssertIntEquals (test, 0x1f8, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_extra_sector_for_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0x200, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_extra_sector_for_header_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 2);
	CuAssertIntEquals (test, 0x200, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_extra_sector_for_iv
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 508, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0x208, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_extra_sector_for_iv_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 508, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 2);
	CuAssertIntEquals (test, 0x208, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_longer_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_old_format (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_static_init
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_invalid_id (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_invalid_id
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_read_header_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_invalid_header_marker (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xb5, 0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_short_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x03, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_invalid_data_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x10};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_invalid_data_length_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x23, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_old_format_invalid_data_length
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x00, 0x10};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.get_data_length (&store.test.base.base, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[250];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_large_buffer (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_corrupt_data_integrity_check (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_INTEGRITY_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_corrupt_data_length_check
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_LENGTH_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_corrupt_data_padding_check (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_PADDING_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_extra_sector_for_iv_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[251];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_large_buffer (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_corrupt_data_integrity_check
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_INTEGRITY_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_corrupt_data_length_check
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_LENGTH_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_corrupt_data_padding_check
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_PADDING_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_multiple_sectors_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_extra_sector_for_iv_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[254];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_corrupt_data_integrity_check (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_INTEGRITY_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_corrupt_data_length_check (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_LENGTH_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_corrupt_data_padding_check (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_PADDING_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_max_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x0f};
	uint8_t data[0x1000 - (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_min_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_extra_sector_for_header_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};
	uint8_t data[508];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_extra_sector_for_iv_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};
	uint8_t data[508];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_longer_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x08, 0x01, 0x02};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_old_format (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[252];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_corrupt_data_integrity_check
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_INTEGRITY_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_corrupt_data_length_check
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_LENGTH_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_corrupt_data_padding_check
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_PADDING_CHECK_FAIL, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_max_length
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x0f};
	uint8_t data[0x1000 - (AES_KEY_WRAP_INTERFACE_BLOCK_SIZE * 2)];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_min_length
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_multiple_sectors_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};
	uint8_t data[504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_extra_sector_for_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_extra_sector_for_header_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};
	uint8_t data[508];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_extra_sector_for_iv_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};
	uint8_t data[508];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_longer_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x08, 0x01, 0x02};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_old_format
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, sizeof (data), &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_static_init
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t data[256];
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (sizeof (data))];
	uint8_t out[0x1000] = {0};
	size_t in_length = sizeof (out);
	size_t out_length = sizeof (data);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		if (i < sizeof (data)) {
			data[i] = i;
		}

		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));
	status |= mock_expect_output (&store.key_wrap.mock, 2, data, sizeof (data), -1);
	status |= mock_expect_output (&store.key_wrap.mock, 3, &out_length, sizeof (out_length), -1);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t out[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256)] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (NULL, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.base.read (&store.test.base.base, 0, NULL, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_invalid_id (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t out[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256)] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 3, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.base.read (&store.test.base.base, -1, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_small_buffer (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t out[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256) - 1] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_BUFFER_TOO_SMALL, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_read_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t out[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256)] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_key_unwrap_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256)] = {0};
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_UNWRAP_FAILED, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, AES_KEY_WRAP_UNWRAP_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_null (CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (NULL, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.base.read (&store.test.base.base, 0, NULL, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_invalid_id (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 3, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.base.read (&store.test.base.base, -1, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_small_buffer (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t out[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256) - 1] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_BUFFER_TOO_SMALL, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_read_header_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_invalid_header_marker
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xb5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_short_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x03, 0xa5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_invalid_data_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x10};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_invalid_data_length_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x03, 0x01};
	uint8_t enc[256 + 3];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_old_format_invalid_data_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x00, 0x10};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_read_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (256));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_key_unwrap_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};
	uint8_t enc[AES_KEY_WRAP_INTERFACE_WRAPPED_LENGTH (256)] = {0};
	uint8_t out[sizeof (enc)] = {0};
	size_t in_length = sizeof (out);
	size_t i;

	TEST_START;

	for (i = 0; i < (int) sizeof (enc); i++) {
		enc[i] = ~i;
	}

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.key_wrap.mock, store.key_wrap.base.unwrap, &store.key_wrap,
		AES_KEY_WRAP_UNWRAP_FAILED, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG_PTR_CONTAINS (&in_length, sizeof (in_length)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.read (&store.test.base.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, AES_KEY_WRAP_UNWRAP_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_not_key_wrap_aligned (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 241, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 512, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_decreasing (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_decreasing_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 260, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_decreasing_multiple_sectors
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_decreasing_static_init (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_fixed_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_max_length
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x0f};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_multiple_sectors (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_multiple_sectors_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_extra_sector_for_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_extra_sector_for_header_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_extra_sector_for_iv (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 508, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_extra_sector_for_iv_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 508, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_longer_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_old_format
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_static_init
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test = flash_store_contiguous_blocks_key_wrap_static_init_variable_storage (&store.state,
			&store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_last_block (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_max_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x0f};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_multiple_sectors
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_multiple_sectors_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf8, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 504 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_extra_sector_for_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_extra_sector_for_header_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 512 - AES_KEY_WRAP_INTERFACE_BLOCK_SIZE,
		&store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_extra_sector_for_iv
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 508, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_extra_sector_for_iv_last_block
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x08, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, sector,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 508, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_longer_header
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_old_format (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage_decreasing (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_static_init
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store = {
		.test =
			flash_store_contiguous_blocks_key_wrap_static_init_variable_storage_decreasing (
			&store.state, &store.flash.base, 0x10000, 3, &store.key_wrap.base)
	};
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_state (&store.test, 256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_invalid_id (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_fixed_storage (&store.test, &store.state,
		&store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_null (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_invalid_id
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_read_header_error (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_invalid_header_marker (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xb5, 0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_short_header (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x03, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_invalid_data_length (
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x10};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_invalid_data_length_not_key_wrap_aligned
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x23, 0x01};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}

static void
flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_old_format_invalid_data_length
(
	CuTest *test)
{
	struct flash_store_contiguous_blocks_key_wrap_testing store;
	int status;
	uint8_t header[] = {0x00, 0x10};

	TEST_START;

	flash_store_contiguous_blocks_key_wrap_testing_prepare_init (test, &store, 0x100, 0x1000,
		0x100000, 1);

	status = flash_store_contiguous_blocks_key_wrap_init_variable_storage (&store.test,
		&store.state, &store.flash.base, 0x10000, 3, 256, &store.key_wrap.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.base.has_data_stored (&store.test.base.base, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_contiguous_blocks_key_wrap_testing_release (test, &store);
}


// *INDENT-OFF*
TEST_SUITE_START (flash_store_contiguous_blocks_key_wrap);

TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_one_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_one_sector_per_block_max_space_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_multiple_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_multiple_sector_per_block_max_space_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_data_not_sector_aligned_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_extra_sector_for_iv_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_extra_sector_for_iv_with_padding_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_max_data);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_no_data);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_block_too_large);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_sector_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_not_sector_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_device_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_base_out_of_range);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_one_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_one_sector_per_block_not_key_wrap_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_multiple_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_multiple_sector_per_block_not_key_wrap_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_data_not_sector_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_extra_sector_for_iv_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_extra_sector_for_iv_with_padding_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_page_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_min_write_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_one_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_one_sector_per_block_max_space_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_multiple_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_multiple_sector_per_block_max_space_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_data_not_sector_aligned_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_extra_sector_for_iv_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_extra_sector_for_iv_with_padding_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_max_data);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_no_data);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_block_too_large);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_sector_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_not_sector_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_device_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_base_out_of_range);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_one_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_one_sector_per_block_not_key_wrap_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_multiple_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_multiple_sector_per_block_not_key_wrap_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_data_not_sector_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_extra_sector_for_iv_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_extra_sector_for_iv_with_padding_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_page_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_fixed_storage_decreasing_min_write_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_one_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_multiple_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_multiple_sector_per_block_max_space_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_data_not_sector_aligned_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_iv_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_iv_with_padding_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_header_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_max_data);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_no_data);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_block_too_large);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_sector_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_not_sector_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_device_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_base_out_of_range);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_one_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_multiple_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_multiple_sector_per_block_not_key_wrap_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_data_not_sector_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_iv_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_iv_with_padding_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_for_header_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_extra_sector_block_too_large);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_page_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_min_write_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_one_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_multiple_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_multiple_sector_per_block_max_space_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_data_not_sector_aligned_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_iv_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_iv_with_padding_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_header_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_max_data);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_no_data);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_block_too_large);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_sector_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_not_sector_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_device_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_base_out_of_range);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_one_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_multiple_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_multiple_sector_per_block_not_key_wrap_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_data_not_sector_aligned_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_iv_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_iv_with_padding_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_for_header_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_extra_sector_block_too_large);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_page_size_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_init_variable_storage_decreasing_min_write_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_one_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_one_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_decreasing_one_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_decreasing_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_fixed_storage_decreasing_one_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_one_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_one_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_decreasing_one_sector_per_block_max_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_decreasing_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_static_init_variable_storage_decreasing_one_sector_per_block_not_enough_space);
TEST (flash_store_contiguous_blocks_key_wrap_test_release_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_max_data_length_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_flash_size_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_num_blocks_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_less_than_page_size_no_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_less_than_page_size_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_larger_than_page_size_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_pages_aligned_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_pages_not_aligned_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_multiple_store_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_less_than_page_size_no_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_less_than_page_size_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_larger_than_page_size_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_pages_aligned_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_pages_not_aligned_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_multiple_store_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_decreasing_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_max_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_old_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_extra_sector_for_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_extra_sector_for_header_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_less_than_page_size_no_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_less_than_page_size_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_less_than_page_size_last_block_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_less_than_page_size_old_header_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_larger_than_page_size_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_larger_than_page_size_last_block_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_larger_than_page_size_old_header_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_pages_aligned_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_pages_not_aligned_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_multiple_store_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_max_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_old_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_extra_sector_for_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_extra_sector_for_header_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_less_than_page_size_no_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_less_than_page_size_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_less_than_page_size_last_block_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_less_than_page_size_old_header_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_larger_than_page_size_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_larger_than_page_size_last_block_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_larger_than_page_size_old_header_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_pages_aligned_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_pages_not_aligned_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_multiple_store_min_write);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_decreasing_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_invalid_id);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_wrong_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_key_wrap_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_erase_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_write_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_fixed_storage_verify_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_invalid_id);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_too_large);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_key_wrap_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_erase_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_write_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_verify_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_write_header_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_verify_header_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_write_old_header_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_verify_old_header_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_single_page_write_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_single_page_verify_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_multiple_pages_write_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_multiple_pages_verify_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_multiple_pages_write_first_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_write_variable_storage_min_write_multiple_pages_verify_first_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_decreasing_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_decreasing_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_decreasing_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_max_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_extra_sector_for_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_extra_sector_for_header_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_longer_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_old_format);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_max_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_extra_sector_for_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_extra_sector_for_header_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_longer_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_old_format);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_decreasing_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_fixed_storage_invalid_id);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_invalid_id);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_read_header_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_invalid_header_marker);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_short_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_invalid_data_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_invalid_data_length_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_get_data_length_variable_storage_old_format_invalid_data_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_large_buffer);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_corrupt_data_integrity_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_corrupt_data_length_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_corrupt_data_padding_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_large_buffer);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_corrupt_data_integrity_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_corrupt_data_length_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_corrupt_data_padding_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_decreasing_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_corrupt_data_integrity_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_corrupt_data_length_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_corrupt_data_padding_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_max_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_min_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_extra_sector_for_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_extra_sector_for_header_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_longer_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_old_format);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_corrupt_data_integrity_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_corrupt_data_length_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_corrupt_data_padding_check);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_max_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_min_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_extra_sector_for_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_extra_sector_for_header_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_longer_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_old_format);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_decreasing_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_invalid_id);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_small_buffer);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_read_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_fixed_storage_key_unwrap_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_invalid_id);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_small_buffer);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_read_header_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_invalid_header_marker);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_short_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_invalid_data_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_invalid_data_length_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_old_format_invalid_data_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_read_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_read_variable_storage_key_unwrap_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_decreasing_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_decreasing_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_decreasing_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_max_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_extra_sector_for_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_extra_sector_for_header_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_longer_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_old_format);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_max_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_multiple_sectors);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_extra_sector_for_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_extra_sector_for_header_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_extra_sector_for_iv);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_extra_sector_for_iv_last_block);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_longer_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_old_format);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_decreasing_static_init);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_fixed_storage_invalid_id);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_null);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_invalid_id);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_read_header_error);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_invalid_header_marker);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_short_header);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_invalid_data_length);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_invalid_data_length_not_key_wrap_aligned);
TEST (flash_store_contiguous_blocks_key_wrap_test_has_data_stored_variable_storage_old_format_invalid_data_length);

TEST_SUITE_END;
// *INDENT-ON*
