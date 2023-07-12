// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/flash_store_contiguous_blocks.h"
#include "flash/flash_store_contiguous_blocks_encrypted.h"
#include "flash/flash_store_aggregator.h"
#include "flash/flash_store_aggregator_static.h"
#include "testing/mock/flash/flash_store_mock.h"


TEST_SUITE_LABEL ("flash_store_aggregator");


/**
 * Dependencies for testing flash store aggregator.
 */
struct flash_store_aggregator_testing {
	struct flash_store_mock flash_1;				/**< Flash storage device. */
	struct flash_store_mock flash_2;				/**< Flash storage device. */
	const struct flash_store *flash_store_array[2];	/**< Array to store the flash storage. */
	struct flash_store_aggregator test;				/**< Flash storage aggregator under test. */
};


/**
 * Helper to set up dependencies and expectations for flash store initialization.
 *
 * @param test The test framework.
 * @param store Testing dependencies that will be initialized.
 * @param flash_store_mock_1 Number of bytes per programming page.
 * @param flash_store_mock_2 Number of bytes per erase sector.
 */
static void flash_store_aggregator_testing_init_dependencies (CuTest *test,
	struct flash_store_aggregator_testing *store, struct flash_store_mock *flash_store_mock_1,
	struct flash_store_mock *flash_store_mock_2)
{
	int status;

	if (flash_store_mock_1) {
		status = flash_store_mock_init (flash_store_mock_1);
		CuAssertIntEquals (test, 0, status);
		store->flash_store_array[0] = &flash_store_mock_1->base;
	}

	if (flash_store_mock_2) {
		status = flash_store_mock_init (flash_store_mock_2);
		CuAssertIntEquals (test, 0, status);
		store->flash_store_array[1] = &flash_store_mock_2->base;
	}
}

/**
 * Helper to validate mocks and release all testing dependencies.
 *
 * @param test The test framework.
 * @param store Testing dependencies to release.
 */
static void flash_store_aggregator_testing_release_dependencies (CuTest *test,
	struct flash_store_mock *flash_1, struct flash_store_mock *flash_2)
{
	int status;

	status = flash_store_mock_validate_and_release (flash_1);
	status |= flash_store_mock_validate_and_release (flash_2);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper to validate and release all the dependencies and release the aggregator resources
 *
 * @param test The test framework.
 * @param store Testing dependencies to release.
 */
static void flash_store_aggregator_testing_release (CuTest *test,
	struct flash_store_aggregator_testing *store)
{
	flash_store_aggregator_testing_release_dependencies (test, &store->flash_1, &store->flash_2);

	flash_store_aggregator_release (&store->test);
}

/*******************
 * Test cases
 *******************/

static void flash_store_aggregator_test_init (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	status = flash_store_aggregator_init (&store.test, store.flash_store_array, 2);
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

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_init_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	status = flash_store_aggregator_init (NULL, store.flash_store_array, 2);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	status = flash_store_aggregator_init (&store.test, NULL, 2);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_testing_release_dependencies (test, &store.flash_1, &store.flash_2);
}

static void flash_store_aggregator_test_init_flash_store_count_invalid (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	status = flash_store_aggregator_init (&store.test, store.flash_store_array, 0);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_testing_release_dependencies (test, &store.flash_1, &store.flash_2);
}

static void flash_store_aggregator_test_static_init (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);

	TEST_START;

	store.test = aggregator;

	CuAssertPtrNotNull (test, store.test.base.write);
	CuAssertPtrNotNull (test, store.test.base.read);
	CuAssertPtrNotNull (test, store.test.base.erase);
	CuAssertPtrNotNull (test, store.test.base.erase_all);
	CuAssertPtrNotNull (test, store.test.base.get_data_length);
	CuAssertPtrNotNull (test, store.test.base.has_data_stored);
	CuAssertPtrNotNull (test, store.test.base.get_max_data_length);
	CuAssertPtrNotNull (test, store.test.base.get_flash_size);
	CuAssertPtrNotNull (test, store.test.base.get_num_blocks);

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_release_null (CuTest *test)
{
	TEST_START;

	flash_store_aggregator_release (NULL);
}

static void flash_store_aggregator_test_read (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t flash_1_data[256];
	uint8_t flash_2_data[256];
	uint8_t read_data[256];
	uint32_t loop;
	int status;

	TEST_START;

	for (loop = 0; loop < 256; loop++) {
		flash_1_data[loop] = loop;
		flash_2_data[loop] = loop + 1;
	}

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.read, &store.flash_1,
		sizeof (flash_1_data), MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG (256));
	status |= mock_expect_output (&store.flash_1.mock, 1, flash_1_data,
		sizeof (flash_1_data), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2,	34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.read, &store.flash_2,
		sizeof (flash_2_data), MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG (256));
	status |= mock_expect_output (&store.flash_2.mock, 1, flash_2_data,
		sizeof (flash_2_data), -1);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, read_data,
		sizeof(read_data));
	CuAssertIntEquals (test, sizeof (flash_1_data), status);

	status = testing_validate_array (flash_1_data, read_data, status);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 36, read_data,
		sizeof(read_data));
	CuAssertIntEquals (test, sizeof (flash_2_data), status);

	status = testing_validate_array (flash_2_data, read_data, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_read_on_start_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t flash_1_data[256];
	uint8_t flash_2_data[256];
	uint8_t read_data[256];
	uint32_t loop;
	int status;

	TEST_START;

	for (loop = 0; loop < 256; loop++) {
		flash_1_data[loop] = loop;
		flash_2_data[loop] = loop + 1;
	}

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1,	34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.read, &store.flash_1,
		sizeof (flash_1_data), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (256));
	status |= mock_expect_output (&store.flash_1.mock, 1, flash_1_data,
		sizeof (flash_1_data), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1,	34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2,	34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.read, &store.flash_2,
		sizeof (flash_2_data), MOCK_ARG (0), MOCK_ARG_NOT_NULL, MOCK_ARG (256));
	status |= mock_expect_output (&store.flash_2.mock, 1, flash_2_data,
		sizeof (flash_2_data), -1);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 0, read_data,
		sizeof(read_data));
	CuAssertIntEquals (test, sizeof (flash_1_data), status);

	status = testing_validate_array (flash_1_data, read_data, status);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 34, read_data,
		sizeof(read_data));
	CuAssertIntEquals (test, sizeof (flash_2_data), status);

	status = testing_validate_array (flash_2_data, read_data, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_read_on_end_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t flash_1_data[256];
	uint8_t flash_2_data[256];
	uint8_t read_data[256];
	uint32_t loop;
	int status;

	TEST_START;

	for (loop = 0; loop < 256; loop++) {
		flash_1_data[loop] = loop;
		flash_2_data[loop] = loop + 1;
	}

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.read, &store.flash_1,
		sizeof (flash_1_data), MOCK_ARG (33), MOCK_ARG_NOT_NULL, MOCK_ARG (256));
	status |= mock_expect_output (&store.flash_1.mock, 1, flash_1_data,
		sizeof (flash_1_data), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.read, &store.flash_2,
		sizeof (flash_2_data), MOCK_ARG (33), MOCK_ARG_NOT_NULL, MOCK_ARG (256));
	status |= mock_expect_output (&store.flash_2.mock, 1, flash_2_data,
		sizeof (flash_2_data), -1);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 33, read_data,
		sizeof(read_data));
	CuAssertIntEquals (test, sizeof (flash_1_data), status);

	status = testing_validate_array (flash_1_data, read_data, status);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 67, read_data, sizeof(read_data));
	CuAssertIntEquals (test, sizeof (flash_2_data), status);

	status = testing_validate_array (flash_2_data, read_data, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_read_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	uint8_t flash_1_data[256];
	uint8_t flash_2_data[256];
	uint8_t read_data[256];
	uint32_t loop;
	int status;

	TEST_START;

	for (loop = 0; loop < 256; loop++) {
		flash_1_data[loop] = loop;
		flash_2_data[loop] = loop + 1;
	}

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.read, &store.flash_1,
		sizeof (flash_1_data), MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG (256));
	status |= mock_expect_output (&store.flash_1.mock, 1, flash_1_data,
		sizeof (flash_1_data), -1);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2,	34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.read, &store.flash_2,
		sizeof (flash_2_data), MOCK_ARG (2), MOCK_ARG_NOT_NULL, MOCK_ARG (256));
	status |= mock_expect_output (&store.flash_2.mock, 1, flash_2_data,
		sizeof (flash_2_data), -1);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 2, read_data,
		sizeof(read_data));
	CuAssertIntEquals (test, sizeof (flash_1_data), status);

	status = testing_validate_array (flash_1_data, read_data, status);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 36, read_data,
		sizeof(read_data));
	CuAssertIntEquals (test, sizeof (flash_2_data), status);

	status = testing_validate_array (flash_2_data, read_data, status);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_read_fail_invalid_id (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t read_data[256];
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.read (&store.test.base, 68, read_data, sizeof(read_data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_read_fail_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t read_data[256];
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.read (NULL, 68, read_data,
		sizeof(read_data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

static void flash_store_aggregator_test_write (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t data[256] = {0};
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.write, &store.flash_1, 0,
		MOCK_ARG (2), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof(data)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.write, &store.flash_2, 0,
		MOCK_ARG (2), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof(data)));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 36, data, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_write_on_start_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t data[256] = {0};
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.write, &store.flash_1, 0,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof(data)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.write, &store.flash_2, 0,
		MOCK_ARG (0), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof(data)));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 0, data, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 34, data, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_write_on_end_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t data[256] = {0};
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.write, &store.flash_1, 0,
		MOCK_ARG (33), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof(data)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.write, &store.flash_2, 0,
		MOCK_ARG (33), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof(data)));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 33, data, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 67, data, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_write_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	uint8_t data[256] = {0};
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.write, &store.flash_1, 0,
		MOCK_ARG (2), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof(data)));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.write, &store.flash_2, 0,
		MOCK_ARG (2), MOCK_ARG_PTR_CONTAINS (data, sizeof (data)),
		MOCK_ARG (sizeof(data)));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 2, data, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 36, data, sizeof(data));
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_write_fail_invalid_id (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t data[256] = {0};
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1, &store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.write (&store.test.base, 68, data, sizeof(data));
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_write_fail_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	uint8_t data[256] = {0};
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.write (NULL, 2, data, sizeof(data));
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

static void flash_store_aggregator_test_erase (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.erase, &store.flash_1, 0,
		MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.erase, &store.flash_2, 0,
		MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 2);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 36);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_erase_start_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.erase, &store.flash_1, 0,
		MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.erase, &store.flash_2, 0,
		MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 34);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_erase_end_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.erase, &store.flash_1, 0,
		MOCK_ARG (33));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.erase, &store.flash_2, 0,
		MOCK_ARG (33));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 33);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 67);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_erase_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.erase, &store.flash_1, 0,
		MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.erase, &store.flash_2, 0,
		MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 2);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 36);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_erase_fail_invalid_id (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase (&store.test.base, 68);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_erase_fail_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.erase (NULL, 2);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

static void flash_store_aggregator_test_erase_all (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.erase_all, &store.flash_1, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_2.mock, store.flash_2.base.erase_all, &store.flash_2, 0);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase_all (&store.test.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_erase_all_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.erase_all, &store.flash_1, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_2.mock, store.flash_2.base.erase_all, &store.flash_2, 0);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase_all (&store.test.base);
	CuAssertIntEquals (test, 0, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_erase_all_fail (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.erase_all, &store.flash_1, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_2.mock, store.flash_2.base.erase_all, &store.flash_2,
	FLASH_STORE_ERASE_ALL_FAILED);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.erase_all (&store.test.base);
	CuAssertIntEquals (test, FLASH_STORE_ERASE_ALL_FAILED, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_erase_all_fail_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.erase_all (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

static void flash_store_aggregator_test_get_data_length (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.get_data_length,
		&store.flash_1, 256, MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_data_length,
		&store.flash_2, 512, MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_data_length (&store.test.base, 2);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.get_data_length (&store.test.base, 36);
	CuAssertIntEquals (test, 512, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_data_length_start_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.get_data_length,
		&store.flash_1, 256, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_data_length,
		&store.flash_2, 512, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_data_length (&store.test.base, 0);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.get_data_length (&store.test.base, 34);
	CuAssertIntEquals (test, 512, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_data_length_end_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.get_data_length,
		&store.flash_1, 256, MOCK_ARG (33));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_data_length,
		&store.flash_2, 512, MOCK_ARG (33));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_data_length (&store.test.base, 33);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.get_data_length (&store.test.base, 67);
	CuAssertIntEquals (test, 512, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_data_length_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.get_data_length,
		&store.flash_1, 256, MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_data_length,
		&store.flash_2, 512, MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_data_length (&store.test.base, 2);
	CuAssertIntEquals (test, 256, status);

	status = store.test.base.get_data_length (&store.test.base, 36);
	CuAssertIntEquals (test, 512, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_data_length_fail_invalid_id (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_data_length (&store.test.base, 68);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_data_length_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.get_max_data_length (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

static void flash_store_aggregator_test_get_flash_size (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_flash_size,
		&store.flash_1, 256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_2.mock, store.flash_2.base.get_flash_size,
		&store.flash_2, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 512, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_flash_size_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_flash_size,
		&store.flash_1, 256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_2.mock, store.flash_2.base.get_flash_size,
		&store.flash_2, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, 512, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_flash_size_fail (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_flash_size,
		&store.flash_1, 256);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_2.mock, store.flash_2.base.get_flash_size,
		&store.flash_2, FLASH_STORE_INVALID_ARGUMENT);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_flash_size (&store.test.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_flash_size_fail_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.get_flash_size (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

static void flash_store_aggregator_test_get_max_data_length (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_max_data_length,
		&store.flash_1, 256);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_max_data_length,
		&store.flash_2, 512);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 256, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_max_data_length_min_followed_max (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_max_data_length,
		&store.flash_1, 512);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_max_data_length,
		&store.flash_2, 256);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 256, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_max_data_length_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_max_data_length,
		&store.flash_1, 256);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_max_data_length,
		&store.flash_2, 512);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, 256, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_max_data_length_fail (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_max_data_length,
		&store.flash_1, 256);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_max_data_length,
		&store.flash_2, FLASH_STORE_INVALID_ARGUMENT);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_max_data_length (&store.test.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_max_data_length_fail_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.get_max_data_length (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

static void flash_store_aggregator_test_get_num_blocks (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 68, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_num_blocks_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, 68, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_num_blocks_fail (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, FLASH_STORE_INVALID_ARGUMENT);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.get_num_blocks (&store.test.base);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_get_num_blocks_fail_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.get_num_blocks (NULL);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

static void flash_store_aggregator_test_has_data_stored (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.has_data_stored,
		&store.flash_1, 0, MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.has_data_stored,
		&store.flash_2, 1, MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 2);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 36);
	CuAssertIntEquals (test, 1, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_has_data_stored_start_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.has_data_stored,
		&store.flash_1, 0, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.has_data_stored,
		&store.flash_2, 1, MOCK_ARG (0));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 34);
	CuAssertIntEquals (test, 1, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_has_data_stored_end_index (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.has_data_stored,
		&store.flash_1, 0, MOCK_ARG (33));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.has_data_stored,
		&store.flash_2, 1, MOCK_ARG (33));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 33);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 67);
	CuAssertIntEquals (test, 1, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_has_data_stored_static (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	const struct flash_store *flash_store_array[2] =
		{&store.flash_1.base, &store.flash_2.base};
	struct flash_store_aggregator aggregator =
		flash_store_aggregator_static_init (flash_store_array, 2);
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	store.test = aggregator;

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_1.mock, store.flash_1.base.has_data_stored,
		&store.flash_1, 0, MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.has_data_stored,
		&store.flash_2, 1, MOCK_ARG (2));
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 2);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 36);
	CuAssertIntEquals (test, 1, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_has_data_stored_fail_invalid_id (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_testing_init_dependencies (test, &store, &store.flash_1,
		&store.flash_2);

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = mock_expect (&store.flash_1.mock, store.flash_1.base.get_num_blocks,
		&store.flash_1, 34);
	status |= mock_expect (&store.flash_2.mock, store.flash_2.base.get_num_blocks,
		&store.flash_2, 34);
	CuAssertIntEquals (test, 0, status);

	status = store.test.base.has_data_stored (&store.test.base, 68);
	CuAssertIntEquals (test, FLASH_STORE_UNSUPPORTED_ID, status);

	flash_store_aggregator_testing_release (test, &store);
}

static void flash_store_aggregator_test_has_data_stored_fail_aggregator_null (CuTest *test)
{
	struct flash_store_aggregator_testing store;
	int status;

	TEST_START;

	flash_store_aggregator_init (&store.test, store.flash_store_array, 2);

	status = store.test.base.has_data_stored (NULL, 2);
	CuAssertIntEquals (test, FLASH_STORE_INVALID_ARGUMENT, status);

	flash_store_aggregator_release (&store.test);
}

TEST_SUITE_START (flash_store_aggregator);

TEST (flash_store_aggregator_test_init);
TEST (flash_store_aggregator_test_init_null);
TEST (flash_store_aggregator_test_init_flash_store_count_invalid);
TEST (flash_store_aggregator_test_static_init);
TEST (flash_store_aggregator_test_release_null);
TEST (flash_store_aggregator_test_read);
TEST (flash_store_aggregator_test_read_on_start_index);
TEST (flash_store_aggregator_test_read_on_end_index);
TEST (flash_store_aggregator_test_read_static);
TEST (flash_store_aggregator_test_read_fail_invalid_id);
TEST (flash_store_aggregator_test_read_fail_aggregator_null);
TEST (flash_store_aggregator_test_write);
TEST (flash_store_aggregator_test_write_on_start_index);
TEST (flash_store_aggregator_test_write_on_end_index);
TEST (flash_store_aggregator_test_write_static);
TEST (flash_store_aggregator_test_write_fail_invalid_id);
TEST (flash_store_aggregator_test_write_fail_aggregator_null);
TEST (flash_store_aggregator_test_erase);
TEST (flash_store_aggregator_test_erase_start_index);
TEST (flash_store_aggregator_test_erase_end_index);
TEST (flash_store_aggregator_test_erase_static);
TEST (flash_store_aggregator_test_erase_fail_invalid_id);
TEST (flash_store_aggregator_test_erase_fail_aggregator_null);
TEST (flash_store_aggregator_test_erase_all);
TEST (flash_store_aggregator_test_erase_all_static);
TEST (flash_store_aggregator_test_erase_all_fail);
TEST (flash_store_aggregator_test_erase_all_fail_aggregator_null);
TEST (flash_store_aggregator_test_get_data_length);
TEST (flash_store_aggregator_test_get_data_length_start_index);
TEST (flash_store_aggregator_test_get_data_length_end_index);
TEST (flash_store_aggregator_test_get_data_length_static);
TEST (flash_store_aggregator_test_get_data_length_fail_invalid_id);
TEST (flash_store_aggregator_test_get_data_length_aggregator_null);
TEST (flash_store_aggregator_test_get_flash_size);
TEST (flash_store_aggregator_test_get_flash_size_static);
TEST (flash_store_aggregator_test_get_flash_size_fail);
TEST (flash_store_aggregator_test_get_flash_size_fail_aggregator_null);
TEST (flash_store_aggregator_test_get_max_data_length);
TEST (flash_store_aggregator_test_get_max_data_length_min_followed_max);
TEST (flash_store_aggregator_test_get_max_data_length_static);
TEST (flash_store_aggregator_test_get_max_data_length_fail);
TEST (flash_store_aggregator_test_get_max_data_length_fail_aggregator_null);
TEST (flash_store_aggregator_test_get_num_blocks);
TEST (flash_store_aggregator_test_get_num_blocks_static);
TEST (flash_store_aggregator_test_get_num_blocks_fail);
TEST (flash_store_aggregator_test_get_num_blocks_fail_aggregator_null);
TEST (flash_store_aggregator_test_has_data_stored);
TEST (flash_store_aggregator_test_has_data_stored_start_index);
TEST (flash_store_aggregator_test_has_data_stored_end_index);
TEST (flash_store_aggregator_test_has_data_stored_static);
TEST (flash_store_aggregator_test_has_data_stored_fail_invalid_id);
TEST (flash_store_aggregator_test_has_data_stored_fail_aggregator_null);

TEST_SUITE_END;
