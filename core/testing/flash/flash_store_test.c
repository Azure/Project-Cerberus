// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_store.h"
#include "testing/mock/crypto/hash_mock.h"
#include "testing/mock/flash/flash_mock.h"


TEST_SUITE_LABEL ("flash_store");


/**
 * Dependencies for testing flash block storage.
 */
struct flash_store_testing {
	struct flash_mock flash;				/**< The flash device. */
	struct hash_engine_mock hash;			/**< Hash engine for integrity checking. */
	uint32_t page;							/**< Number of bytes per flash programming page. */
	uint32_t sector;						/**< Number of bytes per flash erase sector. */
	uint32_t bytes;							/**< Total storage for the flash flash device. */
	uint32_t min_write;						/**< Minimum number of page programming bytes. */
	struct flash_store test;				/**< Flash storage under test. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param store Testing dependencies to initialize.
 */
static void flash_store_testing_init_dependencies (CuTest *test, struct flash_store_testing *store)
{
	int status;

	status = flash_mock_init (&store->flash);
	CuAssertIntEquals (test, 0, status);

	status = hash_mock_init (&store->hash);
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
static void flash_store_testing_prepare_init (CuTest *test, struct flash_store_testing *store,
	uint32_t page, uint32_t sector, uint32_t bytes, uint32_t min_write)
{
	int status;

	flash_store_testing_init_dependencies (test, store);

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
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param store Testing dependencies to release.
 */
static void flash_store_testing_release_dependencies (CuTest *test,
	struct flash_store_testing *store)
{
	int status;

	status = flash_mock_validate_and_release (&store->flash);
	CuAssertIntEquals (test, 0 ,status);

	status = hash_mock_validate_and_release (&store->hash);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void flash_store_test_init_fixed_storage_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.write);
	CuAssertPtrNotNull (test, store.test.read);
	CuAssertPtrNotNull (test, store.test.erase);
	CuAssertPtrNotNull (test, store.test.erase_all);
	CuAssertPtrNotNull (test, store.test.get_data_length);
	CuAssertPtrNotNull (test, store.test.has_data_stored);
	CuAssertPtrNotNull (test, store.test.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.get_flash_size);
	CuAssertPtrNotNull (test, store.test.get_num_blocks);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 256, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.write);
	CuAssertPtrNotNull (test, store.test.read);
	CuAssertPtrNotNull (test, store.test.erase);
	CuAssertPtrNotNull (test, store.test.erase_all);
	CuAssertPtrNotNull (test, store.test.get_data_length);
	CuAssertPtrNotNull (test, store.test.has_data_stored);
	CuAssertPtrNotNull (test, store.test.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.get_flash_size);
	CuAssertPtrNotNull (test, store.test.get_num_blocks);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 256, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_one_sector_per_block_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xfd000, 3, sector,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_one_sector_with_hash_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xfd000, 3,
		sector - SHA256_HASH_LENGTH, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - SHA256_HASH_LENGTH, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_multiple_sector_per_block_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xff400, 3, 1024,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 1024, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_data_not_sector_aligned_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xffa00, 3, 384, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 384, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_extra_sector_for_hash_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xffa00, 3, sector,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_max_data_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		(64 * 1024) - 1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (64 * 1024) - 1, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_max_data_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		(64 * 1024) - 1, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (64 * 1024) - 1, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 0x11000, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_fixed_storage (NULL, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_init_fixed_storage (&store.test, NULL, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_no_data (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 0, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_block_too_large (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xfe000, 3, 64 * 1024,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_sector_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_not_sector_aligned (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10100, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_device_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_base_out_of_range (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, bytes, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_one_sector_per_block_not_enough_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xfe000, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_one_sector_with_hash_not_enough_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xfe000, 3,
		sector - SHA256_HASH_LENGTH, &store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_multiple_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xff500, 3, 1024,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_data_not_sector_aligned_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xffb00, 3, 384,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_extra_sector_for_hash_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0xffb00, 3, sector,
		&store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_page_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_min_write_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.write);
	CuAssertPtrNotNull (test, store.test.read);
	CuAssertPtrNotNull (test, store.test.erase);
	CuAssertPtrNotNull (test, store.test.erase_all);
	CuAssertPtrNotNull (test, store.test.get_data_length);
	CuAssertPtrNotNull (test, store.test.has_data_stored);
	CuAssertPtrNotNull (test, store.test.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.get_flash_size);
	CuAssertPtrNotNull (test, store.test.get_num_blocks);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 256, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.write);
	CuAssertPtrNotNull (test, store.test.read);
	CuAssertPtrNotNull (test, store.test.erase);
	CuAssertPtrNotNull (test, store.test.erase_all);
	CuAssertPtrNotNull (test, store.test.get_data_length);
	CuAssertPtrNotNull (test, store.test.has_data_stored);
	CuAssertPtrNotNull (test, store.test.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.get_flash_size);
	CuAssertPtrNotNull (test, store.test.get_num_blocks);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 256, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_one_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x2000, 3,
		sector, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_one_sector_with_hash_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x2000, 3,
		sector - SHA256_HASH_LENGTH, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - SHA256_HASH_LENGTH, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_multiple_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x800, 3,
		1024, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 1024, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_data_not_sector_aligned_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x400, 3,
		384, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 384, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_extra_sector_for_hash_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x400, 3,
		sector, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_max_data_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0xf0000, 3,
		(64 * 1024) - 1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (64 * 1024) - 1, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_max_data_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0xf0000, 3,
		(64 * 1024) - 1, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (64 * 1024) - 1, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 0x11000, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_fixed_storage_decreasing_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_fixed_storage_decreasing (NULL, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, NULL, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_no_data (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 0,
		256, NULL);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_block_too_large (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0xfe000, 3,
		64 * 1024, NULL);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_sector_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_not_sector_aligned (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10100, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_device_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_base_out_of_range (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, bytes, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_base_zero (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0, 3, 256,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_one_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x1000, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_one_sector_with_hash_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x1000, 3,
		sector - SHA256_HASH_LENGTH, &store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_multiple_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x700, 3,
		1024, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_data_not_sector_aligned_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x300, 3,
		384, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_extra_sector_for_hash_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x300, 3,
		sector, &store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_page_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_fixed_storage_decreasing_min_write_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 0,
		NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.write);
	CuAssertPtrNotNull (test, store.test.read);
	CuAssertPtrNotNull (test, store.test.erase);
	CuAssertPtrNotNull (test, store.test.erase_all);
	CuAssertPtrNotNull (test, store.test.get_data_length);
	CuAssertPtrNotNull (test, store.test.has_data_stored);
	CuAssertPtrNotNull (test, store.test.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.get_flash_size);
	CuAssertPtrNotNull (test, store.test.get_num_blocks);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 0,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.write);
	CuAssertPtrNotNull (test, store.test.read);
	CuAssertPtrNotNull (test, store.test.erase);
	CuAssertPtrNotNull (test, store.test.erase_all);
	CuAssertPtrNotNull (test, store.test.get_data_length);
	CuAssertPtrNotNull (test, store.test.has_data_stored);
	CuAssertPtrNotNull (test, store.test.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.get_flash_size);
	CuAssertPtrNotNull (test, store.test.get_num_blocks);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - sizeof (struct flash_store_header) - 32, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_one_sector_per_block_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xfd000, 3, 0,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_one_sector_with_hash_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xfd000, 3, 0,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - sizeof (struct flash_store_header) - 32, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_multiple_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xff400, 3,
		1024 - sizeof (struct flash_store_header), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 1024 - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_data_not_sector_aligned_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xffa00, 3, 384,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (sector * 2) - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_extra_sector_for_hash_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xffa00, 3,
		sector - sizeof (struct flash_store_header), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (sector * 2) - sizeof (struct flash_store_header) - 32, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_extra_sector_for_header_max_space (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xffa00, 3, sector,
		NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (sector * 2) - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_max_data_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		(64 * 1024) - sizeof (struct flash_store_header), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (64 * 1024) - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_max_data_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		(64 * 1024) - sizeof (struct flash_store_header) - 32, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (64 * 1024) - sizeof (struct flash_store_header) - 32, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_variable_storage (NULL, &store.flash.base, 0x10000, 3, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_init_variable_storage (&store.test, NULL, 0x10000, 3, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_no_data (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 0, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_block_too_large (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xfe000, 3,
		64 * 1024, NULL);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_sector_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_not_sector_aligned (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10100, 3, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_device_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_base_out_of_range (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, bytes, 3, 0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_one_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xfe000, 3, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_one_sector_with_hash_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xfe000, 3, 0,
		&store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_multiple_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xff500, 3,
		1024 - sizeof (struct flash_store_header), NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_data_not_sector_aligned_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xffb00, 3, 384,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_extra_sector_for_hash_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xffb00, 3,
		sector - sizeof (struct flash_store_header), &store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_extra_sector_for_header_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0xffb00, 3, sector,
		NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_extra_sector_for_hash_block_too_large (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		(64 * 1024) - sizeof (struct flash_store_header), &store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_extra_sector_for_header_block_too_large (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		(64 * 1024) - 1, NULL);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_page_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_min_write_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 0,
		NULL);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 0, NULL);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.write);
	CuAssertPtrNotNull (test, store.test.read);
	CuAssertPtrNotNull (test, store.test.erase);
	CuAssertPtrNotNull (test, store.test.erase_all);
	CuAssertPtrNotNull (test, store.test.get_data_length);
	CuAssertPtrNotNull (test, store.test.has_data_stored);
	CuAssertPtrNotNull (test, store.test.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.get_flash_size);
	CuAssertPtrNotNull (test, store.test.get_num_blocks);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 0, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.write);
	CuAssertPtrNotNull (test, store.test.read);
	CuAssertPtrNotNull (test, store.test.erase);
	CuAssertPtrNotNull (test, store.test.erase_all);
	CuAssertPtrNotNull (test, store.test.get_data_length);
	CuAssertPtrNotNull (test, store.test.has_data_stored);
	CuAssertPtrNotNull (test, store.test.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.get_flash_size);
	CuAssertPtrNotNull (test, store.test.get_num_blocks);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - sizeof (struct flash_store_header) - 32, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_one_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x2000,
		3, 0, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_one_sector_with_hash_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x2000,
		3, 0, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, sector - sizeof (struct flash_store_header) - 32, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_multiple_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x800, 3,
		1024 - sizeof (struct flash_store_header), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, 1024 - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_data_not_sector_aligned_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x400, 3,
		384, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (sector * 2) - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_extra_sector_for_hash_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x400, 3,
		sector - sizeof (struct flash_store_header), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (sector * 2) - sizeof (struct flash_store_header) - 32, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_extra_sector_for_header_max_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x400, 3,
		sector, NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (sector * 2) - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_max_data_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0xf0000,
		3, (64 * 1024) - sizeof (struct flash_store_header), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (64 * 1024) - sizeof (struct flash_store_header), status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_max_data_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0xf0000,
		3, (64 * 1024) - sizeof (struct flash_store_header) - 32, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (&store.test);
	CuAssertIntEquals (test, (64 * 1024) - sizeof (struct flash_store_header) - 32, status);

	status = store.test.get_flash_size (&store.test);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.get_num_blocks (&store.test);
	CuAssertIntEquals (test, 3, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_init_variable_storage_decreasing_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_variable_storage_decreasing (NULL, &store.flash.base, 0x10000,
		3, 0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, NULL, 0x10000,
		3, 0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_no_data (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		0, 0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_block_too_large (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0xfe000,
		3, 64 * 1024, NULL);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_sector_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 0, NULL);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_not_sector_aligned (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10100,
		3, 0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_device_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 0, NULL);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_base_out_of_range (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, bytes, 3,
		0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_one_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x1000,
		3, 0, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_one_sector_with_hash_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x1000,
		3, 0, &store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_multiple_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x700, 3,
		1024 - sizeof (struct flash_store_header), NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_data_not_sector_aligned_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x300, 3,
		384, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_extra_sector_for_hash_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x300, 3,
		sector - sizeof (struct flash_store_header), &store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_extra_sector_for_header_not_enough_space (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x300, 3,
		sector, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_extra_sector_for_hash_block_too_large (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0xf0000,
		3, (64 * 1024) - sizeof (struct flash_store_header), &store.hash.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_extra_sector_for_header_block_too_large (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0xf0000,
		3, (64 * 1024) - 1, NULL);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_page_size_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 0, NULL);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_init_variable_storage_decreasing_min_write_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_testing_init_dependencies (test, &store);

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

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 0, NULL);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);
}

static void flash_store_test_release_null (CuTest *test)
{
	TEST_START;

	flash_store_release (NULL);
}

static void flash_store_test_get_max_data_length_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_max_data_length (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_flash_size_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_flash_size (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_num_blocks_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_num_blocks (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (data),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_multiple_sectors_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10400, sizeof (data),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10400), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[384];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_multiple_pages_algined_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_multiple_pages_not_algined_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[768];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_no_hash_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[384];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10800 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, sizeof (data));
	memcpy (&write[sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, sizeof (data));
	memcpy (&write[sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[(sizeof (data) % page) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[page], sizeof (data) - page);
	memcpy (&write[sizeof (data) - page], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[(sizeof (data) % page) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[page], sizeof (data) - page);
	memcpy (&write[sizeof (data) - page], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, data, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[512];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[(page * 2) + 128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[128 + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[sizeof (data) - 128], 128);
	memcpy (&write[128], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_hash_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &hash[extra],
		sizeof (hash) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_hash_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0x12000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page, &hash[extra],
		sizeof (hash) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_multiple_pages_hash_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[sizeof (data) - (page - extra)], page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3), &hash[extra],
		sizeof (hash) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_multiple_pages_hash_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[sizeof (data) - (page - extra)], page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0x12000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + (page * 3), &hash[extra],
		sizeof (hash) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_with_hash_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[(sizeof (data) % page) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[page], sizeof (data) - page);
	memcpy (&write[sizeof (data) - page], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (data),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xfc00, sizeof (data),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0xfc00), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[384];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[768];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[384];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0xf800 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, sizeof (data));
	memcpy (&write[sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, sizeof (data));
	memcpy (&write[sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[(sizeof (data) % page) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[page], sizeof (data) - page);
	memcpy (&write[sizeof (data) - page], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[(sizeof (data) % page) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[page], sizeof (data) - page);
	memcpy (&write[sizeof (data) - page], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (data, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, data, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[512];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (data), hash,
		sizeof (hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[(page * 2) + 128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[128 + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[sizeof (data) - 128], 128);
	memcpy (&write[128], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_hash_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &hash[extra],
		sizeof (hash) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_hash_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0xe000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, &hash[extra],
		sizeof (hash) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_pages_hash_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[sizeof (data) - (page - extra)], page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3), &hash[extra],
		sizeof (hash) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_pages_hash_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[sizeof (data) - (page - extra)], page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0xe000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + (page * 3), &hash[extra],
		sizeof (hash) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[(sizeof (data) % page) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, &data[page], sizeof (data) - page);
	memcpy (&write[sizeof (data) - page], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x12000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_max_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x0f};
	uint8_t data[0x1000 - sizeof (header)];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_old_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (data),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10400, sizeof (data),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10400 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10400), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_extra_sector_for_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t write[sizeof (data) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t write[sizeof (data) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_less_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t write[sizeof (data) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x12000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_larger_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[512 - sizeof (header)];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x02};
	uint8_t data[(page * 2) + 128];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_max_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xdc, 0x0f};
	uint8_t data[0x1000 - sizeof (header) - SHA256_HASH_LENGTH];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_old_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10800 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10800 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (header) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (header) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_less_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (header) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (data) - write_data_len) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[write_data_len], sizeof (data) - write_data_len);
	memcpy (&write2[sizeof (data) - write_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (data) - write_data_len) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[write_data_len], sizeof (data) - write_data_len);
	memcpy (&write2[sizeof (data) - write_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_larger_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (data) - write_data_len) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[write_data_len], sizeof (data) - write_data_len);
	memcpy (&write2[sizeof (data) - write_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[512 - sizeof (header)];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x02};
	uint8_t data[(page * 2) + 128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int write2_data_len = (sizeof (data) % page) + sizeof (header);
	uint8_t write2[write2_data_len + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_hash_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page,
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_hash_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x12000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page,
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_multiple_pages_hash_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3),
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_multiple_pages_hash_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x12000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x12000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x12000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + (page * 3),
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (data) - write_data_len) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[write_data_len], sizeof (data) - write_data_len);
	memcpy (&write2[sizeof (data) - write_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0xe000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_old_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_multiple_sectors (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (data),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xfc00, sizeof (data),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0xfc00 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xfc00), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t write[sizeof (data) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t write[sizeof (data) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_less_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t write[sizeof (data) + sizeof (header)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0xe000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_larger_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[512 - sizeof (header)];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x02};
	uint8_t data[(page * 2) + 128];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_no_hash_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_old_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0xf800 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0xf800 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (header) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (header) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_less_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x80, 0x00};
	uint8_t data[128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[sizeof (data) + sizeof (header) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (data) - write_data_len) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[write_data_len], sizeof (data) - write_data_len);
	memcpy (&write2[sizeof (data) - write_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (data) - write_data_len) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[write_data_len], sizeof (data) - write_data_len);
	memcpy (&write2[sizeof (data) - write_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0xe000 + page), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_larger_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (data) - write_data_len) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[write_data_len], sizeof (data) - write_data_len);
	memcpy (&write2[sizeof (data) - write_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[512 - sizeof (header)];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (data) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], sizeof (data) - write_data_len),
		MOCK_ARG (sizeof (data) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		sizeof (data) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (data), hash, sizeof (hash));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x02};
	uint8_t data[(page * 2) + 128];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int write2_data_len = (sizeof (data) % page) + sizeof (header);
	uint8_t write2[write2_data_len + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_hash_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page,
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_hash_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0xe000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page,
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_multiple_pages_hash_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3),
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_multiple_pages_hash_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0xe000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0xe000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0xe000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + (page * 3),
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_decreasing_with_hash_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (data) - write_data_len) + sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[write_data_len], sizeof (data) - write_data_len);
	memcpy (&write2[sizeof (data) - write_data_len], hash, sizeof (hash));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

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

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.write (NULL, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.write (&store.test, 0, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.write (&store.test, 0, data, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 3, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.write (&store.test, -1, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_wrong_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data) - 1);
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	status = store.test.write (&store.test, 0, data, sizeof (data) + 1);
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_erase_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_write_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_verify_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_write_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_verify_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)),
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_min_write_write_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2),
		MOCK_ARG (page * 2));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_min_write_verify_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_min_write_write_last_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + (page * 2)),
		MOCK_ARG_PTR_CONTAINS (write, sizeof (write)), MOCK_ARG (sizeof (write)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_min_write_verify_last_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_min_write_write_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_fixed_storage_min_write_verify_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, data, page - extra);
	memcpy (&write[page - extra], hash, extra);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (data, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, data, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (hash) - extra, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[extra], sizeof (hash) - extra),
		MOCK_ARG (sizeof (hash) - extra));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + (page * 3)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.write (NULL, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.write (&store.test, 0, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.write (&store.test, 0, data, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 3, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.write (&store.test, -1, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_no_hash_too_large (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[0x1000 - sizeof (struct flash_store_header) + 1];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_with_hash_too_large (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[0x1000 - sizeof (struct flash_store_header) - SHA256_HASH_LENGTH + 1];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_erase_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_write_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_verify_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_write_header_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_verify_header_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_write_old_header_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_verify_old_header_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test);

	status = flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), data,
		sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_write_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (struct flash_store_header), data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_verify_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (data),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (struct flash_store_header), data, sizeof (data));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (hash),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header) + sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (hash, sizeof (hash)), MOCK_ARG (sizeof (hash)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header) + sizeof (data)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_single_page_write_hash_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int extra_hash = (sizeof (hash) - extra) + 4;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_single_page_verify_hash_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int extra_hash = (sizeof (hash) - extra) + 4;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + page), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_single_page_write_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page,
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_single_page_verify_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, sizeof (data));
	memcpy (&write[sizeof (header) + sizeof (data)], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page,
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_multiple_pages_write_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int write_data_len = page - 4;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page), MOCK_ARG (page));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_multiple_pages_verify_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int write_data_len = page - 4;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + page), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_multiple_pages_write_last_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int write_data_len = page - 4;
	int write2_data_len = (page - extra) + 4;
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - 4);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + (page * 2)),
		MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)), MOCK_ARG (sizeof (write2)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_multiple_pages_verify_last_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int write_data_len = page - 4;
	int write2_data_len = (page - extra) + 4;
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - 4);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + (page *2)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_multiple_pages_write_hash_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int write_data_len = page - 4;
	int extra_hash = (sizeof (hash) - extra) + 4;
	int write2_data_len = (page - extra) + 4;
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - 4);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_multiple_pages_verify_hash_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	int write_data_len = page - 4;
	int extra_hash = (sizeof (hash) - extra) + 4;
	int write2_data_len = (page - extra) + 4;
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - 4);

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + (page * 3)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_multiple_pages_write_first_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3),
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_write_variable_storage_min_write_multiple_pages_verify_first_error (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_hash = (sizeof (hash) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], data, write_data_len);

	memcpy (write2, &data[sizeof (data) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], hash, extra - sizeof (header));

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&data[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &data[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_hash,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&hash[sizeof (hash) - extra_hash], extra_hash),
		MOCK_ARG (extra_hash));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3),
		&hash[sizeof (hash) - extra_hash], extra_hash);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.write (&store.test, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_use_length_only_header_null (CuTest *test)
{
	TEST_START;

	flash_store_use_length_only_header (NULL);
}

static void flash_store_test_read_fixed_storage_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_no_hash_large_buffer (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_no_hash_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_no_hash_multiple_sectors_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_with_hash_mismatch (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t bad_hash[sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (bad_hash, hash, sizeof (hash));
	bad_hash[1] ^= 0x55;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, bad_hash, sizeof (bad_hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_with_hash_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_no_hash_large_buffer (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_no_hash_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_with_hash_mismatch (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t bad_hash[sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (bad_hash, hash, sizeof (hash));
	bad_hash[1] ^= 0x55;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, bad_hash, sizeof (bad_hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_with_hash_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_decreasing_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_max_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x0f};
	uint8_t data[0x1000 - sizeof (header)];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_min_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_extra_sector_for_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_longer_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_no_hash_old_format (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_with_hash_mismatch (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t bad_hash[sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (bad_hash, hash, sizeof (hash));
	bad_hash[1] ^= 0x55;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, bad_hash, sizeof (bad_hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_with_hash_max_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xdc, 0x0f};
	uint8_t data[0x1000 - sizeof (header) - SHA256_HASH_LENGTH];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_with_hash_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_no_hash_multiple_sectors (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_no_hash_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_no_hash_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};
	uint8_t data[512];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_with_hash_mismatch (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};
	uint8_t bad_hash[sizeof (hash)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	memcpy (bad_hash, hash, sizeof (hash));
	bad_hash[1] ^= 0x55;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, bad_hash, sizeof (bad_hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_with_hash_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_decreasing_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));
	status |= mock_expect_output (&store.hash.mock, 2, hash, sizeof (hash), 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.read (NULL, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.read (&store.test, 0, NULL, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 3, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.read (&store.test, -1, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_small_buffer (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t out[255] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out) + 1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_BUFFER_TOO_SMALL, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_read_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out), NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_read_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_fixed_storage_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t data[256];
	uint8_t out[sizeof (data)] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.read (NULL, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.read (&store.test, 0, NULL, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out), NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 3, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.read (&store.test, -1, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_small_buffer (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t out[255] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out) + 1, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_BUFFER_TOO_SMALL, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_read_header_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_invalid_header_marker (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xb5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_short_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x03, 0xa5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_invalid_data_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfd, 0x0f};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_old_format_invalid_data_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0xfd, 0x0f};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_read_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (256));

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_read_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_read_variable_storage_hash_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t out[0x1000] = {0};
	size_t i;
	uint8_t hash[] = {
		0x88,0x69,0xde,0x57,0x9d,0xd0,0xe9,0x05,0xe0,0xa7,0x11,0x24,0x57,0x55,0x94,0xf5,
		0x0a,0x03,0xd3,0xd9,0xcd,0xf1,0x6e,0x9a,0x3f,0x9d,0x6c,0x60,0xc0,0x32,0x4b,0x54
	};

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)));
	status |= mock_expect_output (&store.flash.mock, 1, data, sizeof (data), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (data)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (hash)));
	status |= mock_expect_output (&store.flash.mock, 1, hash, sizeof (hash), 2);

	status |= mock_expect (&store.hash.mock, store.hash.base.calculate_sha256, &store.hash,
		HASH_ENGINE_SHA256_FAILED, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (SHA256_HASH_LENGTH));

	CuAssertIntEquals (test, 0, status);

	status = store.test.read (&store.test, 0, out, sizeof (out));
	CuAssertIntEquals (test, HASH_ENGINE_SHA256_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0x12000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_multiple_sectors_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10400, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_extra_sector_for_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10800, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_decreasing (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_decreasing_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0xe000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_decreasing_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_decreasing_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xfc00, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_decreasing_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		512, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_decreasing_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		512, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xf800, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0x12000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_multiple_sectors_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10400, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_extra_sector_for_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10800, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_extra_sector_for_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10800, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_decreasing (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_decreasing_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0xe000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_decreasing_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_decreasing_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xfc00, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_decreasing_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_decreasing_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xf800, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_decreasing_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_decreasing_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xf800, sector * 2,
		sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 2);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.erase (&store.test, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_fixed_storage_erase_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.erase (&store.test, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_variable_storage_erase_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase (&store.test, 0);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_fixed_storage (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0x10000, 0x1000 * 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_fixed_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_fixed_storage_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_fixed_storage_decreasing (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0xe000, 0x1000 * 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_fixed_storage_decreasing_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xfc00,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_fixed_storage_decreasing_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage_decreasing (&store.test, &store.flash.base, 0x10000, 3,
		512, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xf800,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0x10000, 0x1000 * 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_extra_sector_for_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_extra_sector_for_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0x10000,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_decreasing (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify (&store.flash, 0xe000, 0x1000 * 3);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_decreasing_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xfc00,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_decreasing_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xf800,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_decreasing_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_expect_erase_flash_sector_verify_ext (&store.flash, 0xf800,
		(sector * 2) * 3, sector);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_fixed_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_fixed_storage_erase_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_erase_all_variable_storage_erase_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.erase_all (&store.test);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_fixed_storage (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_fixed_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 512, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 2);
	CuAssertIntEquals (test, 512, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash_max_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 0xffc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash_multiple_sectors (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 0x1fc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 2);
	CuAssertIntEquals (test, 0x1fc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 0x1fc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 2);
	CuAssertIntEquals (test, 0x1fc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash_longer_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_no_hash_old_format (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_with_hash_max_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xdc, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 0xfdc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_with_hash_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 2);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_no_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 2);
	CuAssertIntEquals (test, 512, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_no_hash_max_length (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 0xffc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_no_hash_multiple_sectors (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 0x1fc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 2);
	CuAssertIntEquals (test, 0x1fc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_no_hash_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 0x1fc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_no_hash_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 2);
	CuAssertIntEquals (test, 0x1fc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_with_hash_max_length (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xdc, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 0xfdc, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_with_hash_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_decreasing_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 2);
	CuAssertIntEquals (test, 256, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_fixed_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_fixed_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.get_data_length (&store.test, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.get_data_length (&store.test, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_read_header_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_invalid_header_marker (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xb5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_short_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x03, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_invalid_data_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfd, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_get_data_length_variable_storage_old_format_invalid_data_length (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0xfd, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.get_data_length (&store.test, 0);
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_fixed_storage (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_fixed_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash_last_block (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash_max_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash_multiple_sectors (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 512,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash_longer_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_no_hash_old_format (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_with_hash_max_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xdc, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_with_hash_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 508,
		&store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_no_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x02};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_max_length (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_multiple_sectors (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 512, NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_with_hash (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_with_hash_max_length (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xdc, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_with_hash_extra_sector_for_hash (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_decreasing_with_hash_extra_sector_for_hash_last_block (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_init_variable_storage_decreasing (&store.test, &store.flash.base, 0x10000,
		3, 508, &store.hash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 2);
	CuAssertIntEquals (test, 1, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_fixed_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_fixed_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3, 256, NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.has_data_stored (&store.test, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_null (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (NULL, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_invalid_id (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 3);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.has_data_stored (&store.test, -1);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_read_header_error (CuTest *test)
{
	struct flash_store_testing store;
	int status;

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_invalid_header_marker (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xb5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_short_header (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x03, 0xa5, 0x00, 0x01};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_invalid_data_length (CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xfd, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}

static void flash_store_test_has_data_stored_variable_storage_old_format_invalid_data_length (
	CuTest *test)
{
	struct flash_store_testing store;
	int status;
	uint8_t header[] = {0xfd, 0x0f};

	TEST_START;

	flash_store_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_init_variable_storage (&store.test, &store.flash.base, 0x10000, 3, 256,
		NULL);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.has_data_stored (&store.test, 0);
	CuAssertIntEquals (test, 0, status);

	flash_store_testing_release_dependencies (test, &store);

	flash_store_release (&store.test);
}


TEST_SUITE_START (flash_store);

TEST (flash_store_test_init_fixed_storage_no_hash);
TEST (flash_store_test_init_fixed_storage_with_hash);
TEST (flash_store_test_init_fixed_storage_one_sector_per_block_max_space);
TEST (flash_store_test_init_fixed_storage_one_sector_with_hash_max_space);
TEST (flash_store_test_init_fixed_storage_multiple_sector_per_block_max_space);
TEST (flash_store_test_init_fixed_storage_data_not_sector_aligned_max_space);
TEST (flash_store_test_init_fixed_storage_extra_sector_for_hash_max_space);
TEST (flash_store_test_init_fixed_storage_max_data_no_hash);
TEST (flash_store_test_init_fixed_storage_max_data_with_hash);
TEST (flash_store_test_init_fixed_storage_null);
TEST (flash_store_test_init_fixed_storage_no_data);
TEST (flash_store_test_init_fixed_storage_block_too_large);
TEST (flash_store_test_init_fixed_storage_sector_size_error);
TEST (flash_store_test_init_fixed_storage_not_sector_aligned);
TEST (flash_store_test_init_fixed_storage_device_size_error);
TEST (flash_store_test_init_fixed_storage_base_out_of_range);
TEST (flash_store_test_init_fixed_storage_one_sector_per_block_not_enough_space);
TEST (flash_store_test_init_fixed_storage_one_sector_with_hash_not_enough_space);
TEST (flash_store_test_init_fixed_storage_multiple_sector_per_block_not_enough_space);
TEST (flash_store_test_init_fixed_storage_data_not_sector_aligned_not_enough_space);
TEST (flash_store_test_init_fixed_storage_extra_sector_for_hash_not_enough_space);
TEST (flash_store_test_init_fixed_storage_decreasing_no_hash);
TEST (flash_store_test_init_fixed_storage_decreasing_with_hash);
TEST (flash_store_test_init_fixed_storage_decreasing_one_sector_per_block_max_space);
TEST (flash_store_test_init_fixed_storage_decreasing_one_sector_with_hash_max_space);
TEST (flash_store_test_init_fixed_storage_decreasing_multiple_sector_per_block_max_space);
TEST (flash_store_test_init_fixed_storage_decreasing_data_not_sector_aligned_max_space);
TEST (flash_store_test_init_fixed_storage_decreasing_extra_sector_for_hash_max_space);
TEST (flash_store_test_init_fixed_storage_page_size_error);
TEST (flash_store_test_init_fixed_storage_min_write_error);
TEST (flash_store_test_init_fixed_storage_decreasing_max_data_no_hash);
TEST (flash_store_test_init_fixed_storage_decreasing_max_data_with_hash);
TEST (flash_store_test_init_fixed_storage_decreasing_null);
TEST (flash_store_test_init_fixed_storage_decreasing_no_data);
TEST (flash_store_test_init_fixed_storage_decreasing_block_too_large);
TEST (flash_store_test_init_fixed_storage_decreasing_sector_size_error);
TEST (flash_store_test_init_fixed_storage_decreasing_not_sector_aligned);
TEST (flash_store_test_init_fixed_storage_decreasing_device_size_error);
TEST (flash_store_test_init_fixed_storage_decreasing_base_out_of_range);
TEST (flash_store_test_init_fixed_storage_decreasing_base_zero);
TEST (flash_store_test_init_fixed_storage_decreasing_one_sector_per_block_not_enough_space);
TEST (flash_store_test_init_fixed_storage_decreasing_one_sector_with_hash_not_enough_space);
TEST (flash_store_test_init_fixed_storage_decreasing_multiple_sector_per_block_not_enough_space);
TEST (flash_store_test_init_fixed_storage_decreasing_data_not_sector_aligned_not_enough_space);
TEST (flash_store_test_init_fixed_storage_decreasing_extra_sector_for_hash_not_enough_space);
TEST (flash_store_test_init_fixed_storage_decreasing_page_size_error);
TEST (flash_store_test_init_fixed_storage_decreasing_min_write_error);
TEST (flash_store_test_init_variable_storage_no_hash);
TEST (flash_store_test_init_variable_storage_with_hash);
TEST (flash_store_test_init_variable_storage_one_sector_per_block_max_space);
TEST (flash_store_test_init_variable_storage_one_sector_with_hash_max_space);
TEST (flash_store_test_init_variable_storage_multiple_sector_per_block_max_space);
TEST (flash_store_test_init_variable_storage_data_not_sector_aligned_max_space);
TEST (flash_store_test_init_variable_storage_extra_sector_for_hash_max_space);
TEST (flash_store_test_init_variable_storage_extra_sector_for_header_max_space);
TEST (flash_store_test_init_variable_storage_max_data_no_hash);
TEST (flash_store_test_init_variable_storage_max_data_with_hash);
TEST (flash_store_test_init_variable_storage_null);
TEST (flash_store_test_init_variable_storage_no_data);
TEST (flash_store_test_init_variable_storage_block_too_large);
TEST (flash_store_test_init_variable_storage_sector_size_error);
TEST (flash_store_test_init_variable_storage_not_sector_aligned);
TEST (flash_store_test_init_variable_storage_device_size_error);
TEST (flash_store_test_init_variable_storage_base_out_of_range);
TEST (flash_store_test_init_variable_storage_one_sector_per_block_not_enough_space);
TEST (flash_store_test_init_variable_storage_one_sector_with_hash_not_enough_space);
TEST (flash_store_test_init_variable_storage_multiple_sector_per_block_not_enough_space);
TEST (flash_store_test_init_variable_storage_data_not_sector_aligned_not_enough_space);
TEST (flash_store_test_init_variable_storage_extra_sector_for_hash_not_enough_space);
TEST (flash_store_test_init_variable_storage_extra_sector_for_header_not_enough_space);
TEST (flash_store_test_init_variable_storage_extra_sector_for_hash_block_too_large);
TEST (flash_store_test_init_variable_storage_extra_sector_for_header_block_too_large);
TEST (flash_store_test_init_variable_storage_page_size_error);
TEST (flash_store_test_init_variable_storage_min_write_error);
TEST (flash_store_test_init_variable_storage_decreasing_no_hash);
TEST (flash_store_test_init_variable_storage_decreasing_with_hash);
TEST (flash_store_test_init_variable_storage_decreasing_one_sector_per_block_max_space);
TEST (flash_store_test_init_variable_storage_decreasing_one_sector_with_hash_max_space);
TEST (flash_store_test_init_variable_storage_decreasing_multiple_sector_per_block_max_space);
TEST (flash_store_test_init_variable_storage_decreasing_data_not_sector_aligned_max_space);
TEST (flash_store_test_init_variable_storage_decreasing_extra_sector_for_hash_max_space);
TEST (flash_store_test_init_variable_storage_decreasing_extra_sector_for_header_max_space);
TEST (flash_store_test_init_variable_storage_decreasing_max_data_no_hash);
TEST (flash_store_test_init_variable_storage_decreasing_max_data_with_hash);
TEST (flash_store_test_init_variable_storage_decreasing_null);
TEST (flash_store_test_init_variable_storage_decreasing_no_data);
TEST (flash_store_test_init_variable_storage_decreasing_block_too_large);
TEST (flash_store_test_init_variable_storage_decreasing_sector_size_error);
TEST (flash_store_test_init_variable_storage_decreasing_not_sector_aligned);
TEST (flash_store_test_init_variable_storage_decreasing_device_size_error);
TEST (flash_store_test_init_variable_storage_decreasing_base_out_of_range);
TEST (flash_store_test_init_variable_storage_decreasing_one_sector_per_block_not_enough_space);
TEST (flash_store_test_init_variable_storage_decreasing_one_sector_with_hash_not_enough_space);
TEST (flash_store_test_init_variable_storage_decreasing_multiple_sector_per_block_not_enough_space);
TEST (flash_store_test_init_variable_storage_decreasing_data_not_sector_aligned_not_enough_space);
TEST (flash_store_test_init_variable_storage_decreasing_extra_sector_for_hash_not_enough_space);
TEST (flash_store_test_init_variable_storage_decreasing_extra_sector_for_header_not_enough_space);
TEST (flash_store_test_init_variable_storage_decreasing_extra_sector_for_hash_block_too_large);
TEST (flash_store_test_init_variable_storage_decreasing_extra_sector_for_header_block_too_large);
TEST (flash_store_test_init_variable_storage_decreasing_page_size_error);
TEST (flash_store_test_init_variable_storage_decreasing_min_write_error);
TEST (flash_store_test_release_null);
TEST (flash_store_test_get_max_data_length_null);
TEST (flash_store_test_get_flash_size_null);
TEST (flash_store_test_get_num_blocks_null);
TEST (flash_store_test_write_fixed_storage_no_hash);
TEST (flash_store_test_write_fixed_storage_no_hash_last_block);
TEST (flash_store_test_write_fixed_storage_no_hash_multiple_sectors);
TEST (flash_store_test_write_fixed_storage_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_write_fixed_storage_no_hash_less_than_page_size_no_min_write);
TEST (flash_store_test_write_fixed_storage_no_hash_less_than_page_size_min_write);
TEST (flash_store_test_write_fixed_storage_no_hash_larger_than_page_size_min_write);
TEST (flash_store_test_write_fixed_storage_no_hash_multiple_pages_algined_min_write);
TEST (flash_store_test_write_fixed_storage_no_hash_multiple_pages_not_algined_min_write);
TEST (flash_store_test_write_fixed_storage_no_hash_multiple_store_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash);
TEST (flash_store_test_write_fixed_storage_with_hash_extra_sector_for_hash);
TEST (flash_store_test_write_fixed_storage_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_write_fixed_storage_with_hash_less_than_page_size_no_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_less_than_page_size_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_less_than_page_size_last_block_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_larger_than_page_size_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_larger_than_page_size_last_block_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_multiple_pages_aligned_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_multiple_pages_not_aligned_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_hash_across_page_boundary_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_hash_across_page_boundary_last_block_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_multiple_pages_hash_across_page_boundary_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_multiple_pages_hash_across_page_boundary_last_block_min_write);
TEST (flash_store_test_write_fixed_storage_with_hash_multiple_store_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_last_block);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_sectors);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_less_than_page_size_no_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_less_than_page_size_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_larger_than_page_size_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_pages_aligned_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_pages_not_aligned_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_no_hash_multiple_store_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_extra_sector_for_hash);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_less_than_page_size_no_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_less_than_page_size_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_less_than_page_size_last_block_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_larger_than_page_size_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_larger_than_page_size_last_block_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_pages_aligned_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_pages_not_aligned_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_hash_across_page_boundary_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_hash_across_page_boundary_last_block_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_pages_hash_across_page_boundary_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_pages_hash_across_page_boundary_last_block_min_write);
TEST (flash_store_test_write_fixed_storage_decreasing_with_hash_multiple_store_min_write);
TEST (flash_store_test_write_variable_storage_no_hash);
TEST (flash_store_test_write_variable_storage_no_hash_last_block);
TEST (flash_store_test_write_variable_storage_no_hash_max_length);
TEST (flash_store_test_write_variable_storage_no_hash_old_header);
TEST (flash_store_test_write_variable_storage_no_hash_multiple_sectors);
TEST (flash_store_test_write_variable_storage_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_write_variable_storage_no_hash_extra_sector_for_header);
TEST (flash_store_test_write_variable_storage_no_hash_extra_sector_for_header_last_block);
TEST (flash_store_test_write_variable_storage_no_hash_less_than_page_size_no_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_less_than_page_size_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_less_than_page_size_last_block_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_less_than_page_size_old_header_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_larger_than_page_size_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_larger_than_page_size_last_block_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_larger_than_page_size_old_header_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_multiple_pages_aligned_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_multiple_pages_not_aligned_min_write);
TEST (flash_store_test_write_variable_storage_no_hash_multiple_store_min_write);
TEST (flash_store_test_write_variable_storage_with_hash);
TEST (flash_store_test_write_variable_storage_with_hash_max_length);
TEST (flash_store_test_write_variable_storage_with_hash_old_header);
TEST (flash_store_test_write_variable_storage_with_hash_extra_sector_for_hash);
TEST (flash_store_test_write_variable_storage_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_write_variable_storage_with_hash_less_than_page_size_no_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_less_than_page_size_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_less_than_page_size_last_block_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_less_than_page_size_old_header_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_larger_than_page_size_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_larger_than_page_size_last_block_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_larger_than_page_size_old_header_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_multiple_pages_aligned_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_multiple_pages_not_aligned_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_hash_across_page_boundary_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_hash_across_page_boundary_last_block_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_multiple_pages_hash_across_page_boundary_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_multiple_pages_hash_across_page_boundary_last_block_min_write);
TEST (flash_store_test_write_variable_storage_with_hash_multiple_store_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_last_block);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_old_header);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_extra_sector_for_header);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_extra_sector_for_header_last_block);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_multiple_sectors);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_less_than_page_size_no_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_less_than_page_size_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_less_than_page_size_last_block_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_less_than_page_size_old_header_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_larger_than_page_size_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_larger_than_page_size_last_block_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_larger_than_page_size_old_header_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_multiple_pages_aligned_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_multiple_pages_not_aligned_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_no_hash_multiple_store_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_old_header);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_extra_sector_for_hash);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_less_than_page_size_no_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_less_than_page_size_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_less_than_page_size_last_block_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_less_than_page_size_old_header_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_larger_than_page_size_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_larger_than_page_size_last_block_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_larger_than_page_size_old_header_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_multiple_pages_aligned_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_multiple_pages_not_aligned_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_hash_across_page_boundary_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_hash_across_page_boundary_last_block_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_multiple_pages_hash_across_page_boundary_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_multiple_pages_hash_across_page_boundary_last_block_min_write);
TEST (flash_store_test_write_variable_storage_decreasing_with_hash_multiple_store_min_write);
TEST (flash_store_test_write_fixed_storage_null);
TEST (flash_store_test_write_fixed_storage_invalid_id);
TEST (flash_store_test_write_fixed_storage_wrong_length);
TEST (flash_store_test_write_fixed_storage_erase_error);
TEST (flash_store_test_write_fixed_storage_write_error);
TEST (flash_store_test_write_fixed_storage_verify_error);
TEST (flash_store_test_write_fixed_storage_hash_error);
TEST (flash_store_test_write_fixed_storage_write_hash_error);
TEST (flash_store_test_write_fixed_storage_verify_hash_error);
TEST (flash_store_test_write_fixed_storage_min_write_write_error);
TEST (flash_store_test_write_fixed_storage_min_write_verify_error);
TEST (flash_store_test_write_fixed_storage_min_write_write_last_error);
TEST (flash_store_test_write_fixed_storage_min_write_verify_last_error);
TEST (flash_store_test_write_fixed_storage_min_write_write_hash_error);
TEST (flash_store_test_write_fixed_storage_min_write_verify_hash_error);
TEST (flash_store_test_write_variable_storage_null);
TEST (flash_store_test_write_variable_storage_invalid_id);
TEST (flash_store_test_write_variable_storage_no_hash_too_large);
TEST (flash_store_test_write_variable_storage_with_hash_too_large);
TEST (flash_store_test_write_variable_storage_erase_error);
TEST (flash_store_test_write_variable_storage_write_error);
TEST (flash_store_test_write_variable_storage_verify_error);
TEST (flash_store_test_write_variable_storage_write_header_error);
TEST (flash_store_test_write_variable_storage_verify_header_error);
TEST (flash_store_test_write_variable_storage_write_old_header_error);
TEST (flash_store_test_write_variable_storage_verify_old_header_error);
TEST (flash_store_test_write_variable_storage_hash_error);
TEST (flash_store_test_write_variable_storage_write_hash_error);
TEST (flash_store_test_write_variable_storage_verify_hash_error);
TEST (flash_store_test_write_variable_storage_min_write_single_page_write_hash_error);
TEST (flash_store_test_write_variable_storage_min_write_single_page_verify_hash_error);
TEST (flash_store_test_write_variable_storage_min_write_single_page_write_error);
TEST (flash_store_test_write_variable_storage_min_write_single_page_verify_error);
TEST (flash_store_test_write_variable_storage_min_write_multiple_pages_write_error);
TEST (flash_store_test_write_variable_storage_min_write_multiple_pages_verify_error);
TEST (flash_store_test_write_variable_storage_min_write_multiple_pages_write_last_error);
TEST (flash_store_test_write_variable_storage_min_write_multiple_pages_verify_last_error);
TEST (flash_store_test_write_variable_storage_min_write_multiple_pages_write_hash_error);
TEST (flash_store_test_write_variable_storage_min_write_multiple_pages_verify_hash_error);
TEST (flash_store_test_write_variable_storage_min_write_multiple_pages_write_first_error);
TEST (flash_store_test_write_variable_storage_min_write_multiple_pages_verify_first_error);
TEST (flash_store_test_use_length_only_header_null);
TEST (flash_store_test_read_fixed_storage_no_hash);
TEST (flash_store_test_read_fixed_storage_no_hash_last_block);
TEST (flash_store_test_read_fixed_storage_no_hash_large_buffer);
TEST (flash_store_test_read_fixed_storage_no_hash_multiple_sectors);
TEST (flash_store_test_read_fixed_storage_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_read_fixed_storage_with_hash);
TEST (flash_store_test_read_fixed_storage_with_hash_mismatch);
TEST (flash_store_test_read_fixed_storage_with_hash_extra_sector_for_hash);
TEST (flash_store_test_read_fixed_storage_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_read_fixed_storage_decreasing_no_hash);
TEST (flash_store_test_read_fixed_storage_decreasing_no_hash_last_block);
TEST (flash_store_test_read_fixed_storage_decreasing_no_hash_large_buffer);
TEST (flash_store_test_read_fixed_storage_decreasing_no_hash_multiple_sectors);
TEST (flash_store_test_read_fixed_storage_decreasing_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_read_fixed_storage_decreasing_with_hash);
TEST (flash_store_test_read_fixed_storage_decreasing_with_hash_mismatch);
TEST (flash_store_test_read_fixed_storage_decreasing_with_hash_extra_sector_for_hash);
TEST (flash_store_test_read_fixed_storage_decreasing_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_read_variable_storage_no_hash);
TEST (flash_store_test_read_variable_storage_no_hash_last_block);
TEST (flash_store_test_read_variable_storage_no_hash_max_length);
TEST (flash_store_test_read_variable_storage_no_hash_min_length);
TEST (flash_store_test_read_variable_storage_no_hash_multiple_sectors);
TEST (flash_store_test_read_variable_storage_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_read_variable_storage_no_hash_extra_sector_for_header);
TEST (flash_store_test_read_variable_storage_no_hash_extra_sector_for_header_last_block);
TEST (flash_store_test_read_variable_storage_no_hash_longer_header);
TEST (flash_store_test_read_variable_storage_no_hash_old_format);
TEST (flash_store_test_read_variable_storage_with_hash);
TEST (flash_store_test_read_variable_storage_with_hash_mismatch);
TEST (flash_store_test_read_variable_storage_with_hash_max_length);
TEST (flash_store_test_read_variable_storage_with_hash_extra_sector_for_hash);
TEST (flash_store_test_read_variable_storage_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_read_variable_storage_decreasing_no_hash);
TEST (flash_store_test_read_variable_storage_decreasing_no_hash_last_block);
TEST (flash_store_test_read_variable_storage_decreasing_no_hash_multiple_sectors);
TEST (flash_store_test_read_variable_storage_decreasing_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_read_variable_storage_decreasing_no_hash_extra_sector_for_header);
TEST (flash_store_test_read_variable_storage_decreasing_no_hash_extra_sector_for_header_last_block);
TEST (flash_store_test_read_variable_storage_decreasing_with_hash);
TEST (flash_store_test_read_variable_storage_decreasing_with_hash_mismatch);
TEST (flash_store_test_read_variable_storage_decreasing_with_hash_extra_sector_for_hash);
TEST (flash_store_test_read_variable_storage_decreasing_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_read_fixed_storage_null);
TEST (flash_store_test_read_fixed_storage_invalid_id);
TEST (flash_store_test_read_fixed_storage_small_buffer);
TEST (flash_store_test_read_fixed_storage_read_error);
TEST (flash_store_test_read_fixed_storage_read_hash_error);
TEST (flash_store_test_read_fixed_storage_hash_error);
TEST (flash_store_test_read_variable_storage_null);
TEST (flash_store_test_read_variable_storage_invalid_id);
TEST (flash_store_test_read_variable_storage_small_buffer);
TEST (flash_store_test_read_variable_storage_read_header_error);
TEST (flash_store_test_read_variable_storage_invalid_header_marker);
TEST (flash_store_test_read_variable_storage_short_header);
TEST (flash_store_test_read_variable_storage_invalid_data_length);
TEST (flash_store_test_read_variable_storage_old_format_invalid_data_length);
TEST (flash_store_test_read_variable_storage_read_error);
TEST (flash_store_test_read_variable_storage_read_hash_error);
TEST (flash_store_test_read_variable_storage_hash_error);
TEST (flash_store_test_erase_fixed_storage);
TEST (flash_store_test_erase_fixed_storage_last_block);
TEST (flash_store_test_erase_fixed_storage_multiple_sectors);
TEST (flash_store_test_erase_fixed_storage_multiple_sectors_last_block);
TEST (flash_store_test_erase_fixed_storage_extra_sector_for_hash);
TEST (flash_store_test_erase_fixed_storage_extra_sector_for_hash_last_block);
TEST (flash_store_test_erase_fixed_storage_decreasing);
TEST (flash_store_test_erase_fixed_storage_decreasing_last_block);
TEST (flash_store_test_erase_fixed_storage_decreasing_multiple_sectors);
TEST (flash_store_test_erase_fixed_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_test_erase_fixed_storage_decreasing_extra_sector_for_hash);
TEST (flash_store_test_erase_fixed_storage_decreasing_extra_sector_for_hash_last_block);
TEST (flash_store_test_erase_variable_storage);
TEST (flash_store_test_erase_variable_storage_last_block);
TEST (flash_store_test_erase_variable_storage_multiple_sectors);
TEST (flash_store_test_erase_variable_storage_multiple_sectors_last_block);
TEST (flash_store_test_erase_variable_storage_extra_sector_for_header);
TEST (flash_store_test_erase_variable_storage_extra_sector_for_header_last_block);
TEST (flash_store_test_erase_variable_storage_extra_sector_for_hash);
TEST (flash_store_test_erase_variable_storage_extra_sector_for_hash_last_block);
TEST (flash_store_test_erase_variable_storage_decreasing);
TEST (flash_store_test_erase_variable_storage_decreasing_last_block);
TEST (flash_store_test_erase_variable_storage_decreasing_multiple_sectors);
TEST (flash_store_test_erase_variable_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_test_erase_variable_storage_decreasing_extra_sector_for_header);
TEST (flash_store_test_erase_variable_storage_decreasing_extra_sector_for_header_last_block);
TEST (flash_store_test_erase_variable_storage_decreasing_extra_sector_for_hash);
TEST (flash_store_test_erase_variable_storage_decreasing_extra_sector_for_hash_last_block);
TEST (flash_store_test_erase_fixed_storage_null);
TEST (flash_store_test_erase_fixed_storage_invalid_id);
TEST (flash_store_test_erase_fixed_storage_erase_error);
TEST (flash_store_test_erase_variable_storage_null);
TEST (flash_store_test_erase_variable_storage_invalid_id);
TEST (flash_store_test_erase_variable_storage_erase_error);
TEST (flash_store_test_erase_all_fixed_storage);
TEST (flash_store_test_erase_all_fixed_storage_multiple_sectors);
TEST (flash_store_test_erase_all_fixed_storage_extra_sector_for_hash);
TEST (flash_store_test_erase_all_fixed_storage_decreasing);
TEST (flash_store_test_erase_all_fixed_storage_decreasing_multiple_sectors);
TEST (flash_store_test_erase_all_fixed_storage_decreasing_extra_sector_for_hash);
TEST (flash_store_test_erase_all_variable_storage);
TEST (flash_store_test_erase_all_variable_storage_multiple_sectors);
TEST (flash_store_test_erase_all_variable_storage_extra_sector_for_header);
TEST (flash_store_test_erase_all_variable_storage_extra_sector_for_hash);
TEST (flash_store_test_erase_all_variable_storage_decreasing);
TEST (flash_store_test_erase_all_variable_storage_decreasing_multiple_sectors);
TEST (flash_store_test_erase_all_variable_storage_decreasing_extra_sector_for_header);
TEST (flash_store_test_erase_all_variable_storage_decreasing_extra_sector_for_hash);
TEST (flash_store_test_erase_all_fixed_storage_null);
TEST (flash_store_test_erase_all_fixed_storage_erase_error);
TEST (flash_store_test_erase_all_variable_storage_null);
TEST (flash_store_test_erase_all_variable_storage_erase_error);
TEST (flash_store_test_get_data_length_fixed_storage);
TEST (flash_store_test_get_data_length_fixed_storage_multiple_sectors);
TEST (flash_store_test_get_data_length_variable_storage_no_hash);
TEST (flash_store_test_get_data_length_variable_storage_no_hash_last_block);
TEST (flash_store_test_get_data_length_variable_storage_no_hash_max_length);
TEST (flash_store_test_get_data_length_variable_storage_no_hash_multiple_sectors);
TEST (flash_store_test_get_data_length_variable_storage_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_get_data_length_variable_storage_no_hash_extra_sector_for_header);
TEST (flash_store_test_get_data_length_variable_storage_no_hash_extra_sector_for_header_last_block);
TEST (flash_store_test_get_data_length_variable_storage_no_hash_longer_header);
TEST (flash_store_test_get_data_length_variable_storage_no_hash_old_format);
TEST (flash_store_test_get_data_length_variable_storage_with_hash);
TEST (flash_store_test_get_data_length_variable_storage_with_hash_max_length);
TEST (flash_store_test_get_data_length_variable_storage_with_hash_extra_sector_for_hash);
TEST (flash_store_test_get_data_length_variable_storage_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_no_hash);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_no_hash_last_block);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_no_hash_max_length);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_no_hash_multiple_sectors);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_no_hash_extra_sector_for_header);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_no_hash_extra_sector_for_header_last_block);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_with_hash);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_with_hash_max_length);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_with_hash_extra_sector_for_hash);
TEST (flash_store_test_get_data_length_variable_storage_decreasing_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_get_data_length_fixed_storage_null);
TEST (flash_store_test_get_data_length_fixed_storage_invalid_id);
TEST (flash_store_test_get_data_length_variable_storage_null);
TEST (flash_store_test_get_data_length_variable_storage_invalid_id);
TEST (flash_store_test_get_data_length_variable_storage_read_header_error);
TEST (flash_store_test_get_data_length_variable_storage_invalid_header_marker);
TEST (flash_store_test_get_data_length_variable_storage_short_header);
TEST (flash_store_test_get_data_length_variable_storage_invalid_data_length);
TEST (flash_store_test_get_data_length_variable_storage_old_format_invalid_data_length);
TEST (flash_store_test_has_data_stored_fixed_storage);
TEST (flash_store_test_has_data_stored_fixed_storage_multiple_sectors);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash_last_block);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash_max_length);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash_multiple_sectors);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash_extra_sector_for_header);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash_extra_sector_for_header_last_block);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash_longer_header);
TEST (flash_store_test_has_data_stored_variable_storage_no_hash_old_format);
TEST (flash_store_test_has_data_stored_variable_storage_with_hash);
TEST (flash_store_test_has_data_stored_variable_storage_with_hash_max_length);
TEST (flash_store_test_has_data_stored_variable_storage_with_hash_extra_sector_for_hash);
TEST (flash_store_test_has_data_stored_variable_storage_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_no_hash);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_last_block);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_max_length);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_multiple_sectors);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_multiple_sectors_last_block);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_extra_sector_for_header);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_no_hash_extra_sector_for_header_last_block);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_with_hash);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_with_hash_max_length);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_with_hash_extra_sector_for_hash);
TEST (flash_store_test_has_data_stored_variable_storage_decreasing_with_hash_extra_sector_for_hash_last_block);
TEST (flash_store_test_has_data_stored_fixed_storage_null);
TEST (flash_store_test_has_data_stored_fixed_storage_invalid_id);
TEST (flash_store_test_has_data_stored_variable_storage_null);
TEST (flash_store_test_has_data_stored_variable_storage_invalid_id);
TEST (flash_store_test_has_data_stored_variable_storage_read_header_error);
TEST (flash_store_test_has_data_stored_variable_storage_invalid_header_marker);
TEST (flash_store_test_has_data_stored_variable_storage_short_header);
TEST (flash_store_test_has_data_stored_variable_storage_invalid_data_length);
TEST (flash_store_test_has_data_stored_variable_storage_old_format_invalid_data_length);

TEST_SUITE_END;
