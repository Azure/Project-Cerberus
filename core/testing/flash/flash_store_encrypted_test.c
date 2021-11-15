// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_store_encrypted.h"
#include "testing/mock/crypto/aes_mock.h"
#include "testing/mock/crypto/rng_mock.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/crypto/aes_testing.h"


TEST_SUITE_LABEL ("flash_store_encrypted");


/**
 * Length of encryption tag data added to each data block.
 */
#define	FLASH_STORE_ENCRYPTED_TEST_TAG_LEN		(AES_IV_LEN + AES_GCM_TAG_LEN)

/**
 * Dependencies for testing encrypted flash block storage.
 */
struct flash_store_encrypted_testing {
	struct flash_mock flash;				/**< The flash device. */
	struct aes_engine_mock aes;				/**< AES engine for data encryption. */
	struct rng_engine_mock rng;				/**< RNG engine to use for testing. */
	uint32_t page;							/**< Number of bytes per flash programming page. */
	uint32_t sector;						/**< Number of bytes per flash erase sector. */
	uint32_t bytes;							/**< Total storage for the flash flash device. */
	uint32_t min_write;						/**< Minimum number of page programming bytes. */
	struct flash_store_encrypted test;		/**< Flash storage under test. */
};

/**
 * Helper to initialize all dependencies for testing.
 *
 * @param test The test framework.
 * @param store Testing dependencies to initailize.
 *
 */
static void flash_store_encrypted_testing_init_dependencies (CuTest *test,
	struct flash_store_encrypted_testing *store)
{
	int status;

	status = flash_mock_init (&store->flash);
	CuAssertIntEquals (test, 0, status);

	status = aes_mock_init (&store->aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_init (&store->rng);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to set up dependencies and expectations for encrypted flash store initialization.
 *
 * @param test The test framework.
 * @param store Testing dependencies that will be initialized.
 * @param page Number of bytes per programming page.
 * @param sector Number of bytes per erase sector.
 * @param bytes Total size of the flash device.
 * @param min_write Minimum number of bytes required to write to a page.
 */
static void flash_store_encrypted_testing_prepare_init (CuTest *test,
	struct flash_store_encrypted_testing *store, uint32_t page, uint32_t sector, uint32_t bytes,
	uint32_t min_write)
{
	int status;

	flash_store_encrypted_testing_init_dependencies (test, store);

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
 *
 */
static void flash_store_encrypted_testing_release_dependencies (CuTest *test,
	struct flash_store_encrypted_testing *store)
{
	int status;

	status = flash_mock_validate_and_release (&store->flash);
	CuAssertIntEquals (test, 0 ,status);

	status = aes_mock_validate_and_release (&store->aes);
	CuAssertIntEquals (test, 0, status);

	status = rng_mock_validate_and_release (&store->rng);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void flash_store_encrypted_test_init_fixed_storage (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.base.write);
	CuAssertPtrNotNull (test, store.test.base.read);
	CuAssertPtrNotNull (test, store.test.base.erase);
	CuAssertPtrNotNull (test, store.test.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.get_num_blocks);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_one_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xfd000, 3,
		sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_multiple_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xff400, 3,
		1024 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 1024 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_data_not_sector_aligned_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xffa00, 3,
		384, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 384, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_extra_sector_for_tag_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xffa00, 3,
		sector, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, sector, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_max_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		(64 * 1024) - 1, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, (64 * 1024) - 1, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * 0x11000, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_fixed_storage (NULL, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, NULL, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, NULL, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_no_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 0,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_block_too_large (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xfe000, 3,
		64 * 1024, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_sector_size_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_not_sector_aligned (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10100, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_device_size_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_base_out_of_range (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, bytes, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_one_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xfe000, 3,
		sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_multiple_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xff500, 3,
		1024 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_data_not_sector_aligned_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xffb00, 3,
		384, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_extra_sector_for_tag_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0xffb00, 3,
		sector, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_page_size_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_min_write_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.base.write);
	CuAssertPtrNotNull (test, store.test.base.read);
	CuAssertPtrNotNull (test, store.test.base.erase);
	CuAssertPtrNotNull (test, store.test.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.get_num_blocks);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_one_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x2000, 3, sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_multiple_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x800, 3, 1024 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 1024 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_data_not_sector_aligned_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x400, 3, 384, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 384, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_extra_sector_for_tag_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x400, 3, sector, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, sector, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_max_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0xf0000, 3, (64 * 1024) - 1, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, (64 * 1024) - 1, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * 0x11000, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_fixed_storage_decreasing (NULL, &store.flash.base,
		0x10000, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, NULL,
		0x10000, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 256, NULL, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 256, &store.aes.base, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_no_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 0, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_block_too_large (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0xfe000, 3, 64 * 1024, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_sector_size_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_not_sector_aligned (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10100, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_device_size_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_base_out_of_range (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		bytes, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_one_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x1000, 3, sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_multiple_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x700, 3, 1024 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_data_not_sector_aligned_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x300, 3, 384, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_extra_sector_for_tag_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x300, 3, sector, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_page_size_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_fixed_storage_decreasing_min_write_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.base.write);
	CuAssertPtrNotNull (test, store.test.base.read);
	CuAssertPtrNotNull (test, store.test.base.erase);
	CuAssertPtrNotNull (test, store.test.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.get_num_blocks);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		sector - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_one_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xfd000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		sector - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_multiple_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xff400,
		3, 1024 - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		&store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		1024 - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_data_not_sector_aligned_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xffa00,
		3, 384, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		(sector * 2) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_extra_sector_for_tag_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xffa00,
		3, sector - sizeof (struct flash_store_header), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		(sector * 2) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_extra_sector_for_header_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xffa00,
		3, sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		(sector * 2) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_max_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, (64 * 1024) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		&store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		(64 * 1024) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_variable_storage (NULL, &store.flash.base, 0x10000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, NULL, 0x10000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 0, NULL, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, NULL, 0x10000,
		3, 0, &store.aes.base, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_no_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		0, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_block_too_large (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xfe000,
		3, 64 * 1024, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_sector_size_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_not_sector_aligned (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10100,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_device_size_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_base_out_of_range (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, bytes, 3,
		0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_one_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xfe000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_multiple_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xff500,
		3, 1024 - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		&store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_data_not_sector_aligned_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xffb00,
		3, 384, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_extra_sector_for_tag_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xffb00,
		3, sector - sizeof (struct flash_store_header), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_extra_sector_for_header_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0xffb00,
		3, sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_extra_sector_block_too_large (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, (64 * 1024) - 1, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_page_size_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_min_write_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, store.test.base.write);
	CuAssertPtrNotNull (test, store.test.base.read);
	CuAssertPtrNotNull (test, store.test.base.erase);
	CuAssertPtrNotNull (test, store.test.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.get_num_blocks);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		sector - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_one_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x2000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		sector - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * sector, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_multiple_sector_per_block_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x800, 3, 1024 - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		&store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		1024 - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * 1024, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_data_not_sector_aligned_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x400, 3, 384, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		(sector * 2) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_for_tag_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x400, 3, sector - sizeof (struct flash_store_header), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		(sector * 2) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_for_header_max_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x400, 3, sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		(sector * 2) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * (sector * 2), status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_max_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;
	uint32_t min_write = 1;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0xf0000, 3,
		(64 * 1024) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		&store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test,
		(64 * 1024) - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 3 * 0x10000, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 3, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_variable_storage_decreasing (NULL, &store.flash.base,
		0x10000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, NULL,
		0x10000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 0, NULL, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 0, &store.aes.base, NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_no_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 0, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_NO_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_block_too_large (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0xfe000, 3, 64 * 1024, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_sector_size_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_not_sector_aligned (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10100, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_STORAGE_NOT_ALIGNED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_device_size_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash,
		FLASH_DEVICE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_DEVICE_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_base_out_of_range (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		bytes, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BAD_BASE_ADDRESS, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_one_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x1000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_multiple_sector_per_block_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x700, 3, 1024 - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN,
		&store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_data_not_sector_aligned_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x300, 3, 384, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_for_tag_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x300, 3, sector - sizeof (struct flash_store_header), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_for_header_not_enough_space (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x300, 3, sector - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_INSUFFICIENT_STORAGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_block_too_large (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0xf0000, 3, (64 * 1024) - 1, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_STORE_BLOCK_TOO_LARGE, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_page_size_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &sector, sizeof (sector), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_device_size, &store.flash, 0,
		MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&store.flash.mock, store.flash.base.get_page_size, &store.flash,
		FLASH_PAGE_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_init_variable_storage_decreasing_min_write_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint32_t sector = 0x1000;
	uint32_t bytes = 0x100000;

	TEST_START;

	flash_store_encrypted_testing_init_dependencies (test, &store);

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

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 0, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, FLASH_MINIMUM_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);
}

static void flash_store_encrypted_test_release_null (CuTest *test)
{
	TEST_START;

	flash_store_encrypted_release (NULL);
}

static void flash_store_encrypted_test_get_max_data_length_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_get_flash_size_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_flash_size (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_get_num_blocks_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_num_blocks (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x12000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10400, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10400), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10400 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_extra_sector_for_tag (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_extra_sector_for_tag_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10800 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (data) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, sizeof (enc));
	memcpy (&write[sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (data) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, sizeof (enc));
	memcpy (&write[sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[(sizeof (data) % page) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[page], sizeof (enc) - page);
	memcpy (&write[sizeof (enc) - page], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[(sizeof (data) % page) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[page], sizeof (enc) - page);
	memcpy (&write[sizeof (enc) - page], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (enc, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, enc, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[(page * 2) + 128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[128 + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[sizeof (enc) - 128], 128);
	memcpy (&write[128], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_tag_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &tag[extra],
		sizeof (tag) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_tag_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0x12000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page, &tag[extra],
		sizeof (tag) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_multiple_pages_tag_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[sizeof (enc) - (page - extra)], page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3), &tag[extra],
		sizeof (tag) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_multiple_pages_tag_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[sizeof (enc) - (page - extra)], page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0x12000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + (page * 3), &tag[extra],
		sizeof (tag) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_multiple_store_min_write (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[(sizeof (data) % page) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[page], sizeof (enc) - page);
	memcpy (&write[sizeof (enc) - page], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0xe000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_sectors (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xfc00, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xfc00), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0xfc00 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_extra_sector_for_tag (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status |= mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_extra_sector_for_tag_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0xf800 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (data) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, sizeof (enc));
	memcpy (&write[sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (data) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, sizeof (enc));
	memcpy (&write[sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[(sizeof (data) % page) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[page], sizeof (enc) - page);
	memcpy (&write[sizeof (enc) - page], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[(sizeof (data) % page) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[page], sizeof (enc) - page);
	memcpy (&write[sizeof (enc) - page], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (enc, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, enc, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (enc), tag,
		sizeof (tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[(page * 2) + 128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[128 + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[sizeof (enc) - 128], 128);
	memcpy (&write[128], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_tag_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &tag[extra],
		sizeof (tag) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_tag_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0xe000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, &tag[extra],
		sizeof (tag) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_pages_tag_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[sizeof (enc) - (page - extra)], page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3), &tag[extra],
		sizeof (tag) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_pages_tag_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[sizeof (enc) - (page - extra)], page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0xe000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + (page * 3), &tag[extra],
		sizeof (tag) - extra);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[(sizeof (data) % page) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, &enc[page], sizeof (enc) - page);
	memcpy (&write[sizeof (enc) - page], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, page, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page), MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x12000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x12000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x12000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_max_length (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x0f};
	uint8_t data[0x1000 - sizeof (header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_old_header (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test.base);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x01};
	uint8_t data[508 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x01};
	uint8_t data[508 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10400, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10400 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10400 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10400 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10400), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10400, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_extra_sector_for_header (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xe4, 0x01};
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xe4, 0x01};
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10800 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10800 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_extra_sector_for_tag (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_extra_sector_for_tag_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10800 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10800 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (enc) + sizeof (header) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (enc) + sizeof (header) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_less_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x80, 0x00};
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (enc) + sizeof (header) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test.base);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);
	memcpy (&write2[sizeof (enc) - write_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);
	memcpy (&write2[sizeof (enc) - write_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_larger_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x80, 0x01};
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);
	memcpy (&write2[sizeof (enc) - write_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test.base);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[512 - sizeof (header)];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (enc) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], sizeof (enc) - write_data_len),
		MOCK_ARG (sizeof (enc) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		sizeof (enc) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x02};
	uint8_t data[(page * 2) + 128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int write2_data_len = (sizeof (enc) % page) + sizeof (header);
	uint8_t write2[write2_data_len + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_tag_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page,
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_tag_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x12000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page,
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_multiple_pages_tag_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3),
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_multiple_pages_tag_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x12000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x12000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x12000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x12000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000 + (page * 3),
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x12000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x12000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);
	memcpy (&write2[sizeof (enc) - write_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xe000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0xe000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0xe000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_max_length (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x0f};
	uint8_t data[0x1000 - sizeof (header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_old_header (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test.base);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_multiple_sectors (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x01};
	uint8_t data[508 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x01};
	uint8_t data[508 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xfc00, sizeof (enc),
		sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xfc00 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0xfc00 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00 + sizeof (header) + sizeof (enc),
		tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xfc00), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xfc00, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xe4, 0x01};
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xe4, 0x01};
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0xf800 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (header) + sizeof (enc),
		tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_extra_sector_for_tag (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0x10000, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_extra_sector_for_tag_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector_ext (&store.flash, 0xf800, sector * 2, sector);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0xf800 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800 + sizeof (header) + sizeof (enc),
		tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0xf800), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xf800, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_less_than_page_size_no_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, header, sizeof (header));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_less_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (enc) + sizeof (header) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_less_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x00};
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (enc) + sizeof (header) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_less_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x80, 0x00};
	uint8_t data[128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[sizeof (enc) + sizeof (header) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test.base);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_larger_than_page_size_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);
	memcpy (&write2[sizeof (enc) - write_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_larger_than_page_size_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);
	memcpy (&write2[sizeof (enc) - write_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_larger_than_page_size_old_header_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x80, 0x01};
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);
	memcpy (&write2[sizeof (enc) - write_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test.base);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_multiple_pages_aligned_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[512 - sizeof (header)];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (enc) - write_data_len, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], sizeof (enc) - write_data_len),
		MOCK_ARG (sizeof (enc) - write_data_len));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		sizeof (enc) - write_data_len);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_multiple_pages_not_aligned_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x02};
	uint8_t data[(page * 2) + 128];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int write2_data_len = (sizeof (enc) % page) + sizeof (header);
	uint8_t write2[write2_data_len + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_tag_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page,
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_tag_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0xe000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page,
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_multiple_pages_tag_across_page_boundary_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3),
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_multiple_pages_tag_across_page_boundary_last_block_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0xe000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0xe000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0xe000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0xe000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000 + (page * 3),
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0xe000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0xe000, write, sizeof (write));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_decreasing_multiple_store_min_write (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0x80, 0x01};
	uint8_t data[384];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	uint8_t write2[(sizeof (enc) - write_data_len) + sizeof (tag)];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[write_data_len], sizeof (enc) - write_data_len);
	memcpy (&write2[sizeof (enc) - write_data_len], tag, sizeof (tag));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

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

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (NULL, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.write (&store.test.base, 0, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.write (&store.test.base, 0, data, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_invalid_id (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];

	TEST_START;


	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 3, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.write (&store.test.base, -1, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_wrong_length (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data) - 1);
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data) + 1);
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_iv_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_encrypt_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes,
		AES_ENGINE_ENCRYPT_FAILED, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, AES_ENGINE_ENCRYPT_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_erase_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_write_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_verify_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_write_tag_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_verify_tag_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)),
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_min_write_write_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2),
		MOCK_ARG (page * 2));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_min_write_verify_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_min_write_write_last_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + (page * 2)),
		MOCK_ARG_PTR_CONTAINS (write, sizeof (write)), MOCK_ARG (sizeof (write)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_min_write_verify_last_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_min_write_write_tag_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_fixed_storage_min_write_verify_tag_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, enc, page - extra);
	memcpy (&write[page - extra], tag, extra);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page * 2,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (enc, page * 2), MOCK_ARG (page * 2));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000, enc, page * 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write,
		sizeof (write));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		sizeof (tag) - extra, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[extra], sizeof (tag) - extra), MOCK_ARG (sizeof (tag) - extra));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + (page * 3)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (NULL, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.write (&store.test.base, 0, NULL, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.write (&store.test.base, 0, data, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_invalid_id (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];

	TEST_START;


	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 3, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.write (&store.test.base, -1, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_too_large (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[
		0x1000 - sizeof (struct flash_store_header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN + 1];

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_STORE_BAD_DATA_LENGTH, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_iv_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng,
		RNG_ENGINE_RANDOM_FAILED, MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, RNG_ENGINE_RANDOM_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_encrypt_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes,
		AES_ENGINE_ENCRYPT_FAILED, MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof (data)), MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (data)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, AES_ENGINE_ENCRYPT_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_erase_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.get_sector_size, &store.flash,
		FLASH_SECTOR_SIZE_FAILED, MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_write_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_verify_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_write_tag_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (struct flash_store_header), enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_verify_tag_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header)),
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (struct flash_store_header), enc, sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (struct flash_store_header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (struct flash_store_header) + sizeof (data)),
		MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_write_header_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_verify_header_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_write_old_header_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test.base);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_verify_old_header_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_use_length_only_header (&store.test.base);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (enc),
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + sizeof (header), enc,
		sizeof (enc));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (tag),
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (tag, sizeof (tag)), MOCK_ARG (sizeof (tag)));
	status |= flash_mock_expect_verify_flash (&store.flash,
		0x10000 + sizeof (header) + sizeof (enc), tag, sizeof (tag));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (header, sizeof (header)),
		MOCK_ARG (sizeof (header)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_single_page_write_tag_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int extra_tag = (sizeof (tag) - extra) + 4;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_single_page_verify_tag_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int extra_tag = (sizeof (tag) - extra) + 4;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + page), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_single_page_write_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page,
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_single_page_verify_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x00};
	int extra = 16;
	uint8_t data[page - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	uint8_t write[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, sizeof (enc));
	memcpy (&write[sizeof (header) + sizeof (enc)], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page,
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_write_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int write_data_len = page - 4;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + page),
		MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page), MOCK_ARG (page));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_verify_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int write_data_len = page - 4;

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + page), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_write_last_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int write_data_len = page - 4;
	int write2_data_len = (page - extra) + 4;
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - 4);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + (page * 2)),
		MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)), MOCK_ARG (sizeof (write2)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_verify_last_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int write_data_len = page - 4;
	int write2_data_len = (page - extra) + 4;
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - 4);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_write_tag_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int write_data_len = page - 4;
	int extra_tag = (sizeof (tag) - extra) + 4;
	int write2_data_len = (page - extra) + 4;
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - 4);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_verify_tag_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	int write_data_len = page - 4;
	int extra_tag = (sizeof (tag) - extra) + 4;
	int write2_data_len = (page - extra) + 4;
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - 4);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + (page * 3)), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_write_first_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3),
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash,
		FLASH_WRITE_FAILED, MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_WRITE_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_verify_first_error (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t page = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xf0, 0x02};
	int extra = 16;
	uint8_t data[(page * 3) - extra];
	uint8_t enc[sizeof (data)];
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t write[page];
	int write_data_len = page - sizeof (header);
	int extra_tag = (sizeof (tag) - extra) + sizeof (header);
	int write2_data_len = (page - extra) + sizeof (header);
	uint8_t write2[page];

	TEST_START;

	for (i = 0; i < sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	memcpy (write, header, sizeof (header));
	memcpy (&write[sizeof (header)], enc, write_data_len);

	memcpy (write2, &enc[sizeof (enc) - write2_data_len], write2_data_len);
	memcpy (&write2[write2_data_len], tag, extra - sizeof (header));

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 0x100);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.rng.mock, store.rng.base.generate_random_buffer, &store.rng, 0,
		MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&store.rng.mock, 1, AES_IV, AES_IV_LEN, 0);

	status |= mock_expect (&store.aes.mock, store.aes.base.encrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (data, sizeof (data)), MOCK_ARG (sizeof (data)),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (AES_GCM_TAG_LEN));
	status |= mock_expect_output (&store.aes.mock, 4, enc, sizeof (enc), 5);
	status |= mock_expect_output (&store.aes.mock, 6, AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN, 7);

	status |= flash_mock_expect_erase_flash_sector (&store.flash, 0x10000, 0x1000);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, page,
		MOCK_ARG (0x10000 + page), MOCK_ARG_PTR_CONTAINS (&enc[write_data_len], page),
		MOCK_ARG (page));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + page, &enc[write_data_len],
		page);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write2),
		MOCK_ARG (0x10000 + (page * 2)), MOCK_ARG_PTR_CONTAINS (write2, sizeof (write2)),
		MOCK_ARG (sizeof (write2)));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 2), write2,
		sizeof (write2));

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, extra_tag,
		MOCK_ARG (0x10000 + (page * 3)),
		MOCK_ARG_PTR_CONTAINS (&tag[sizeof (tag) - extra_tag], extra_tag), MOCK_ARG (extra_tag));
	status |= flash_mock_expect_verify_flash (&store.flash, 0x10000 + (page * 3),
		&tag[sizeof (tag) - extra_tag], extra_tag);

	status |= mock_expect (&store.flash.mock, store.flash.base.write, &store.flash, sizeof (write),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (write, sizeof (write)),
		MOCK_ARG (sizeof (write)));
	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG_ANY);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof (data));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_large_buffer (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_corrupt_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes,
		AES_ENGINE_GCM_AUTH_FAILED, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_multiple_sectors_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_extra_sector_for_tag (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_extra_sector_for_tag_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decreasing (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decreasing_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decreasing_large_buffer (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decreasing_corrupt_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes,
		AES_ENGINE_GCM_AUTH_FAILED, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decreasing_multiple_sectors (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decreasing_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decreasing_extra_sector_for_tag (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decreasing_extra_sector_for_tag_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t data[512];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x12000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_corrupt_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes,
		AES_ENGINE_GCM_AUTH_FAILED, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_max_length (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x0f};
	uint8_t data[0x1000 - sizeof (header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_min_length (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_multiple_sectors (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x01};
	uint8_t data[508 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x01};
	uint8_t data[508 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10400 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_extra_sector_for_header (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xe4, 0x01};
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xe4, 0x01};
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_extra_sector_for_tag (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_extra_sector_for_tag_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10800 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_longer_header (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_old_format (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_last_block (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xe000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_corrupt_data (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes,
		AES_ENGINE_GCM_AUTH_FAILED, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_CORRUPT_DATA, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_max_length (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x0f};
	uint8_t data[0x1000 - sizeof (header) - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_min_length (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[sizeof (data)] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_multiple_sectors (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x01};
	uint8_t data[508 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_multiple_sectors_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x100;
	uint8_t header[] = {0x04, 0xa5, 0xe0, 0x01};
	uint8_t data[508 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xfc00 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_extra_sector_for_header (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xe4, 0x01};
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_extra_sector_for_header_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xe4, 0x01};
	uint8_t data[512 - FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_extra_sector_for_tag (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_extra_sector_for_tag_last_block (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint32_t sector = 0x200;
	uint8_t header[] = {0x04, 0xa5, 0xfc, 0x01};
	uint8_t data[508];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, sector, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0xf800 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_longer_header (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x05, 0xa5, 0x00, 0x01, 0x02};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decreasing_old_format (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x00, 0x01};
	uint8_t data[256];
	uint8_t enc[sizeof (data)];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (data); i++) {
		data[i] = i;
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage_decreasing (&store.test, &store.flash.base,
		0x10000, 3, sizeof (data), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes, 0,
		MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)), MOCK_ARG (sizeof (enc)),
		MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.aes.mock, 5, data, sizeof (data), 6);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, sizeof (data), status);

	status = testing_validate_array (data, out, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (NULL, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.read (&store.test.base, 0, NULL, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_invalid_id (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 3, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.read (&store.test.base, -1, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_small_buffer (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t out[255] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out) + 1, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_BUFFER_TOO_SMALL, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_read_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (out), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_read_tag_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t enc[256];
	uint8_t out[sizeof (enc)] = {0};
	size_t i;

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		enc[i] = ~i;
	}

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (enc), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FLASH_STORE_ENCRYPTED_TEST_TAG_LEN));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_fixed_storage_decrypt_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t enc[256];
	uint8_t out[sizeof (enc)] = {0};
	size_t i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < sizeof (enc); i++) {
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_fixed_storage (&store.test, &store.flash.base, 0x10000, 3,
		sizeof (enc), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (out)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (enc)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes,
		AES_ENGINE_DECRYPT_FAILED, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)), MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, AES_ENGINE_DECRYPT_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_null (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (out), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (NULL, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = store.test.base.read (&store.test.base, 0, NULL, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_invalid_id (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t out[256] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (out), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 3, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	status = store.test.base.read (&store.test.base, -1, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_small_buffer (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t out[255] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (out) + 1, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_BUFFER_TOO_SMALL, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_read_header_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, FLASH_READ_FAILED,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_invalid_header_marker (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xb5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_short_header (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x03, 0xa5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_invalid_data_length (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0xe1, 0x0f};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_old_format_invalid_data_length (
	CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0xe1, 0x0f};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct flash_store_header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_STORE_NO_DATA, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_read_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, 256, &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (256));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_read_tag_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t enc[256];
	uint8_t out[0x1000] = {0};

	TEST_START;

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (enc), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash,
		FLASH_READ_FAILED, MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (FLASH_STORE_ENCRYPTED_TEST_TAG_LEN));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, FLASH_READ_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}

static void flash_store_encrypted_test_read_variable_storage_decrypt_error (CuTest *test)
{
	struct flash_store_encrypted_testing store;
	int status;
	uint8_t header[] = {0x04, 0xa5, 0x00, 0x01};
	uint8_t enc[256];
	uint8_t out[0x1000] = {0};
	int i;
	uint8_t tag[FLASH_STORE_ENCRYPTED_TEST_TAG_LEN];

	TEST_START;

	for (i = 0; i < (int) sizeof (enc); i++) {
		enc[i] = ~i;
	}

	memcpy (tag, AES_IV, AES_IV_LEN);
	memcpy (&tag[AES_IV_LEN], AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN);

	flash_store_encrypted_testing_prepare_init (test, &store, 0x100, 0x1000, 0x100000, 1);

	status = flash_store_encrypted_init_variable_storage (&store.test, &store.flash.base, 0x10000,
		3, sizeof (enc), &store.aes.base, &store.rng.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (header)));
	status |= mock_expect_output (&store.flash.mock, 1, header, sizeof (header), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header)), MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (enc)));
	status |= mock_expect_output (&store.flash.mock, 1, enc, sizeof (enc), 2);

	status |= mock_expect (&store.flash.mock, store.flash.base.read, &store.flash, 0,
		MOCK_ARG (0x10000 + sizeof (header) + sizeof (enc)), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (tag)));
	status |= mock_expect_output (&store.flash.mock, 1, tag, sizeof (tag), 2);

	status |= mock_expect (&store.aes.mock, store.aes.base.decrypt_data, &store.aes,
		AES_ENGINE_DECRYPT_FAILED, MOCK_ARG_PTR_CONTAINS (enc, sizeof (enc)),
		MOCK_ARG (sizeof (enc)),MOCK_ARG_PTR_CONTAINS (AES_RSA_PRIVKEY_GCM_TAG, AES_GCM_TAG_LEN),
		MOCK_ARG_PTR_CONTAINS (AES_IV, AES_IV_LEN), MOCK_ARG (AES_IV_LEN), MOCK_ARG_NOT_NULL,
		MOCK_ARG (sizeof (enc)));

	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, out, sizeof (out));
	CuAssertIntEquals (test, AES_ENGINE_DECRYPT_FAILED, status);

	flash_store_encrypted_testing_release_dependencies (test, &store);

	flash_store_encrypted_release (&store.test);
}


TEST_SUITE_START (flash_store_encrypted);

TEST (flash_store_encrypted_test_init_fixed_storage);
TEST (flash_store_encrypted_test_init_fixed_storage_one_sector_per_block_max_space);
TEST (flash_store_encrypted_test_init_fixed_storage_multiple_sector_per_block_max_space);
TEST (flash_store_encrypted_test_init_fixed_storage_data_not_sector_aligned_max_space);
TEST (flash_store_encrypted_test_init_fixed_storage_extra_sector_for_tag_max_space);
TEST (flash_store_encrypted_test_init_fixed_storage_max_data);
TEST (flash_store_encrypted_test_init_fixed_storage_null);
TEST (flash_store_encrypted_test_init_fixed_storage_no_data);
TEST (flash_store_encrypted_test_init_fixed_storage_block_too_large);
TEST (flash_store_encrypted_test_init_fixed_storage_sector_size_error);
TEST (flash_store_encrypted_test_init_fixed_storage_not_sector_aligned);
TEST (flash_store_encrypted_test_init_fixed_storage_device_size_error);
TEST (flash_store_encrypted_test_init_fixed_storage_base_out_of_range);
TEST (flash_store_encrypted_test_init_fixed_storage_one_sector_per_block_not_enough_space);
TEST (flash_store_encrypted_test_init_fixed_storage_multiple_sector_per_block_not_enough_space);
TEST (flash_store_encrypted_test_init_fixed_storage_data_not_sector_aligned_not_enough_space);
TEST (flash_store_encrypted_test_init_fixed_storage_extra_sector_for_tag_not_enough_space);
TEST (flash_store_encrypted_test_init_fixed_storage_page_size_error);
TEST (flash_store_encrypted_test_init_fixed_storage_min_write_error);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_one_sector_per_block_max_space);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_multiple_sector_per_block_max_space);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_data_not_sector_aligned_max_space);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_extra_sector_for_tag_max_space);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_max_data);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_null);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_no_data);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_block_too_large);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_sector_size_error);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_not_sector_aligned);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_device_size_error);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_base_out_of_range);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_one_sector_per_block_not_enough_space);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_multiple_sector_per_block_not_enough_space);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_data_not_sector_aligned_not_enough_space);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_extra_sector_for_tag_not_enough_space);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_page_size_error);
TEST (flash_store_encrypted_test_init_fixed_storage_decreasing_min_write_error);
TEST (flash_store_encrypted_test_init_variable_storage);
TEST (flash_store_encrypted_test_init_variable_storage_one_sector_per_block_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_multiple_sector_per_block_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_data_not_sector_aligned_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_extra_sector_for_tag_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_extra_sector_for_header_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_max_data);
TEST (flash_store_encrypted_test_init_variable_storage_null);
TEST (flash_store_encrypted_test_init_variable_storage_no_data);
TEST (flash_store_encrypted_test_init_variable_storage_block_too_large);
TEST (flash_store_encrypted_test_init_variable_storage_sector_size_error);
TEST (flash_store_encrypted_test_init_variable_storage_not_sector_aligned);
TEST (flash_store_encrypted_test_init_variable_storage_device_size_error);
TEST (flash_store_encrypted_test_init_variable_storage_base_out_of_range);
TEST (flash_store_encrypted_test_init_variable_storage_one_sector_per_block_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_multiple_sector_per_block_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_data_not_sector_aligned_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_extra_sector_for_tag_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_extra_sector_for_header_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_extra_sector_block_too_large);
TEST (flash_store_encrypted_test_init_variable_storage_page_size_error);
TEST (flash_store_encrypted_test_init_variable_storage_min_write_error);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_one_sector_per_block_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_multiple_sector_per_block_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_data_not_sector_aligned_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_for_tag_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_for_header_max_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_max_data);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_null);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_no_data);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_block_too_large);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_sector_size_error);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_not_sector_aligned);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_device_size_error);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_base_out_of_range);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_one_sector_per_block_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_multiple_sector_per_block_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_data_not_sector_aligned_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_for_tag_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_for_header_not_enough_space);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_extra_sector_block_too_large);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_page_size_error);
TEST (flash_store_encrypted_test_init_variable_storage_decreasing_min_write_error);
TEST (flash_store_encrypted_test_release_null);
TEST (flash_store_encrypted_test_get_max_data_length_null);
TEST (flash_store_encrypted_test_get_flash_size_null);
TEST (flash_store_encrypted_test_get_num_blocks_null);
TEST (flash_store_encrypted_test_write_fixed_storage);
TEST (flash_store_encrypted_test_write_fixed_storage_last_block);
TEST (flash_store_encrypted_test_write_fixed_storage_multiple_sectors);
TEST (flash_store_encrypted_test_write_fixed_storage_multiple_sectors_last_block);
TEST (flash_store_encrypted_test_write_fixed_storage_extra_sector_for_tag);
TEST (flash_store_encrypted_test_write_fixed_storage_extra_sector_for_tag_last_block);
TEST (flash_store_encrypted_test_write_fixed_storage_less_than_page_size_no_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_less_than_page_size_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_less_than_page_size_last_block_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_larger_than_page_size_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_larger_than_page_size_last_block_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_multiple_pages_aligned_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_multiple_pages_not_aligned_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_tag_across_page_boundary_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_tag_across_page_boundary_last_block_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_multiple_pages_tag_across_page_boundary_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_multiple_pages_tag_across_page_boundary_last_block_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_multiple_store_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_last_block);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_sectors);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_extra_sector_for_tag);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_extra_sector_for_tag_last_block);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_less_than_page_size_no_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_less_than_page_size_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_less_than_page_size_last_block_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_larger_than_page_size_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_larger_than_page_size_last_block_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_pages_aligned_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_pages_not_aligned_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_tag_across_page_boundary_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_tag_across_page_boundary_last_block_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_pages_tag_across_page_boundary_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_pages_tag_across_page_boundary_last_block_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_decreasing_multiple_store_min_write);
TEST (flash_store_encrypted_test_write_variable_storage);
TEST (flash_store_encrypted_test_write_variable_storage_last_block);
TEST (flash_store_encrypted_test_write_variable_storage_max_length);
TEST (flash_store_encrypted_test_write_variable_storage_old_header);
TEST (flash_store_encrypted_test_write_variable_storage_multiple_sectors);
TEST (flash_store_encrypted_test_write_variable_storage_multiple_sectors_last_block);
TEST (flash_store_encrypted_test_write_variable_storage_extra_sector_for_header);
TEST (flash_store_encrypted_test_write_variable_storage_extra_sector_for_header_last_block);
TEST (flash_store_encrypted_test_write_variable_storage_extra_sector_for_tag);
TEST (flash_store_encrypted_test_write_variable_storage_extra_sector_for_tag_last_block);
TEST (flash_store_encrypted_test_write_variable_storage_less_than_page_size_no_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_less_than_page_size_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_less_than_page_size_last_block_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_less_than_page_size_old_header_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_larger_than_page_size_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_larger_than_page_size_last_block_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_larger_than_page_size_old_header_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_multiple_pages_aligned_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_multiple_pages_not_aligned_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_tag_across_page_boundary_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_tag_across_page_boundary_last_block_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_multiple_pages_tag_across_page_boundary_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_multiple_pages_tag_across_page_boundary_last_block_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_multiple_store_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_last_block);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_max_length);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_old_header);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_multiple_sectors);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_extra_sector_for_header);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_extra_sector_for_header_last_block);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_extra_sector_for_tag);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_extra_sector_for_tag_last_block);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_less_than_page_size_no_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_less_than_page_size_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_less_than_page_size_last_block_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_less_than_page_size_old_header_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_larger_than_page_size_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_larger_than_page_size_last_block_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_larger_than_page_size_old_header_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_multiple_pages_aligned_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_multiple_pages_not_aligned_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_tag_across_page_boundary_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_tag_across_page_boundary_last_block_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_multiple_pages_tag_across_page_boundary_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_multiple_pages_tag_across_page_boundary_last_block_min_write);
TEST (flash_store_encrypted_test_write_variable_storage_decreasing_multiple_store_min_write);
TEST (flash_store_encrypted_test_write_fixed_storage_null);
TEST (flash_store_encrypted_test_write_fixed_storage_invalid_id);
TEST (flash_store_encrypted_test_write_fixed_storage_wrong_length);
TEST (flash_store_encrypted_test_write_fixed_storage_iv_error);
TEST (flash_store_encrypted_test_write_fixed_storage_encrypt_error);
TEST (flash_store_encrypted_test_write_fixed_storage_erase_error);
TEST (flash_store_encrypted_test_write_fixed_storage_write_error);
TEST (flash_store_encrypted_test_write_fixed_storage_verify_error);
TEST (flash_store_encrypted_test_write_fixed_storage_write_tag_error);
TEST (flash_store_encrypted_test_write_fixed_storage_verify_tag_error);
TEST (flash_store_encrypted_test_write_fixed_storage_min_write_write_error);
TEST (flash_store_encrypted_test_write_fixed_storage_min_write_verify_error);
TEST (flash_store_encrypted_test_write_fixed_storage_min_write_write_last_error);
TEST (flash_store_encrypted_test_write_fixed_storage_min_write_verify_last_error);
TEST (flash_store_encrypted_test_write_fixed_storage_min_write_write_tag_error);
TEST (flash_store_encrypted_test_write_fixed_storage_min_write_verify_tag_error);
TEST (flash_store_encrypted_test_write_variable_storage_null);
TEST (flash_store_encrypted_test_write_variable_storage_invalid_id);
TEST (flash_store_encrypted_test_write_variable_storage_too_large);
TEST (flash_store_encrypted_test_write_variable_storage_iv_error);
TEST (flash_store_encrypted_test_write_variable_storage_encrypt_error);
TEST (flash_store_encrypted_test_write_variable_storage_erase_error);
TEST (flash_store_encrypted_test_write_variable_storage_write_error);
TEST (flash_store_encrypted_test_write_variable_storage_verify_error);
TEST (flash_store_encrypted_test_write_variable_storage_write_tag_error);
TEST (flash_store_encrypted_test_write_variable_storage_verify_tag_error);
TEST (flash_store_encrypted_test_write_variable_storage_write_header_error);
TEST (flash_store_encrypted_test_write_variable_storage_verify_header_error);
TEST (flash_store_encrypted_test_write_variable_storage_write_old_header_error);
TEST (flash_store_encrypted_test_write_variable_storage_verify_old_header_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_single_page_write_tag_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_single_page_verify_tag_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_single_page_write_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_single_page_verify_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_write_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_verify_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_write_last_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_verify_last_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_write_tag_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_verify_tag_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_write_first_error);
TEST (flash_store_encrypted_test_write_variable_storage_min_write_multiple_pages_verify_first_error);
TEST (flash_store_encrypted_test_read_fixed_storage);
TEST (flash_store_encrypted_test_read_fixed_storage_last_block);
TEST (flash_store_encrypted_test_read_fixed_storage_large_buffer);
TEST (flash_store_encrypted_test_read_fixed_storage_corrupt_data);
TEST (flash_store_encrypted_test_read_fixed_storage_multiple_sectors);
TEST (flash_store_encrypted_test_read_fixed_storage_multiple_sectors_last_block);
TEST (flash_store_encrypted_test_read_fixed_storage_extra_sector_for_tag);
TEST (flash_store_encrypted_test_read_fixed_storage_extra_sector_for_tag_last_block);
TEST (flash_store_encrypted_test_read_fixed_storage_decreasing);
TEST (flash_store_encrypted_test_read_fixed_storage_decreasing_last_block);
TEST (flash_store_encrypted_test_read_fixed_storage_decreasing_large_buffer);
TEST (flash_store_encrypted_test_read_fixed_storage_decreasing_corrupt_data);
TEST (flash_store_encrypted_test_read_fixed_storage_decreasing_multiple_sectors);
TEST (flash_store_encrypted_test_read_fixed_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_encrypted_test_read_fixed_storage_decreasing_extra_sector_for_tag);
TEST (flash_store_encrypted_test_read_fixed_storage_decreasing_extra_sector_for_tag_last_block);
TEST (flash_store_encrypted_test_read_variable_storage);
TEST (flash_store_encrypted_test_read_variable_storage_last_block);
TEST (flash_store_encrypted_test_read_variable_storage_corrupt_data);
TEST (flash_store_encrypted_test_read_variable_storage_max_length);
TEST (flash_store_encrypted_test_read_variable_storage_min_length);
TEST (flash_store_encrypted_test_read_variable_storage_multiple_sectors);
TEST (flash_store_encrypted_test_read_variable_storage_multiple_sectors_last_block);
TEST (flash_store_encrypted_test_read_variable_storage_extra_sector_for_header);
TEST (flash_store_encrypted_test_read_variable_storage_extra_sector_for_header_last_block);
TEST (flash_store_encrypted_test_read_variable_storage_extra_sector_for_tag);
TEST (flash_store_encrypted_test_read_variable_storage_extra_sector_for_tag_last_block);
TEST (flash_store_encrypted_test_read_variable_storage_longer_header);
TEST (flash_store_encrypted_test_read_variable_storage_old_format);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_last_block);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_corrupt_data);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_max_length);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_min_length);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_multiple_sectors);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_multiple_sectors_last_block);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_extra_sector_for_header);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_extra_sector_for_header_last_block);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_extra_sector_for_tag);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_extra_sector_for_tag_last_block);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_longer_header);
TEST (flash_store_encrypted_test_read_variable_storage_decreasing_old_format);
TEST (flash_store_encrypted_test_read_fixed_storage_null);
TEST (flash_store_encrypted_test_read_fixed_storage_invalid_id);
TEST (flash_store_encrypted_test_read_fixed_storage_small_buffer);
TEST (flash_store_encrypted_test_read_fixed_storage_read_error);
TEST (flash_store_encrypted_test_read_fixed_storage_read_tag_error);
TEST (flash_store_encrypted_test_read_fixed_storage_decrypt_error);
TEST (flash_store_encrypted_test_read_variable_storage_null);
TEST (flash_store_encrypted_test_read_variable_storage_invalid_id);
TEST (flash_store_encrypted_test_read_variable_storage_small_buffer);
TEST (flash_store_encrypted_test_read_variable_storage_read_header_error);
TEST (flash_store_encrypted_test_read_variable_storage_invalid_header_marker);
TEST (flash_store_encrypted_test_read_variable_storage_short_header);
TEST (flash_store_encrypted_test_read_variable_storage_invalid_data_length);
TEST (flash_store_encrypted_test_read_variable_storage_old_format_invalid_data_length);
TEST (flash_store_encrypted_test_read_variable_storage_read_error);
TEST (flash_store_encrypted_test_read_variable_storage_read_tag_error);
TEST (flash_store_encrypted_test_read_variable_storage_decrypt_error);

TEST_SUITE_END;
