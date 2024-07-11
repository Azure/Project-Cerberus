// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "testing.h"
#include "common/array_size.h"
#include "common/mmio_util.h"


TEST_SUITE_LABEL ("mmio_util");

/*******************
 * Test cases
 *******************/

static void mmio_register_read32_test (CuTest *test)
{
	uint32_t register_data = 0x11223344;
	uint32_t read_data;

	TEST_START;

	read_data = mmio_register_read32 (&register_data);
	CuAssertIntEquals (test, register_data, read_data);
}

static void mmio_register_write32_test (CuTest *test)
{
	uint32_t register_data = 0x11223344;
	uint32_t written_data;

	TEST_START;

	mmio_register_write32 (&written_data, register_data);
	CuAssertIntEquals (test, register_data, written_data);
}

static void mmio_register_block_read32_test (CuTest *test)
{
	uint32_t register_source_data[] = {0, 1, 2, 3, 4, 5, 6, 7};
	uint32_t read_data[8] = {0};
	int status;

	TEST_START;

	mmio_register_block_read32 (read_data, register_source_data, ARRAY_SIZE (register_source_data));
	status = testing_validate_array (register_source_data, read_data,
		sizeof (register_source_data));
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_read32_test_zero_size (CuTest *test)
{
	uint32_t register_source_data[] = {0, 1, 2, 3, 4, 5, 6, 7};
	uint32_t expected_read_data[8] = {32, 33, 34, 35, 36, 37, 38, 39};
	uint32_t read_data[8] = {32, 33, 34, 35, 36, 37, 38, 39};
	int status;

	TEST_START;

	/* make sure read_data is not modified */
	mmio_register_block_read32 (read_data, register_source_data, 0);
	status = testing_validate_array (expected_read_data, read_data, sizeof (expected_read_data));
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_write32_test (CuTest *test)
{
	uint32_t source_data[] = {0, 1, 2, 3, 4, 5, 6, 7};
	uint32_t written_data[8] = {0};
	int status;

	TEST_START;

	mmio_register_block_write32 (written_data, source_data, ARRAY_SIZE (source_data));
	status = testing_validate_array (source_data, written_data, sizeof (source_data));
	CuAssertIntEquals (test, 0, status);
}

static void mmio_register_block_write32_test_zero_size (CuTest *test)
{
	uint32_t source_data[] = {0, 1, 2, 3, 4, 5, 6, 7};
	uint32_t expected_read_data[8] = {32, 33, 34, 35, 36, 37, 38, 39};
	uint32_t written_data[8] = {32, 33, 34, 35, 36, 37, 38, 39};
	int status;

	TEST_START;

	/* make sure read_data is not modified */
	mmio_register_block_write32 (written_data, source_data, 0);
	status = testing_validate_array (expected_read_data, written_data, sizeof (expected_read_data));
	CuAssertIntEquals (test, 0, status);
}


// *INDENT-OFF*
TEST_SUITE_START (mmio_util);

TEST (mmio_register_read32_test);
TEST (mmio_register_write32_test);
TEST (mmio_register_block_read32_test);
TEST (mmio_register_block_read32_test_zero_size);
TEST (mmio_register_block_write32_test);
TEST (mmio_register_block_write32_test_zero_size);

TEST_SUITE_END;
// *INDENT-ON*
