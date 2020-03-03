// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include "platform.h"
#include "testing.h"
#include "flash/flash.h"
#include "flash/flash_common.h"
#include "mock/flash_mock.h"
#include "tpm/tpm.h"


static const char *SUITE = "tpm";


/**
 * Helper function to setup the TPM for testing.
 *
 * @param test The test framework
 * @param tpm The TPM instance to initialize.
 * @param flash The flash device mock to initialize.
 */
static void setup_tpm_mock_test (CuTest *test, struct tpm *tpm, struct flash_mock *flash)
{
	struct tpm_header header = {0};
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	header.magic = TPM_MAGIC;

	status = flash_mock_init (flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash->mock, flash->base.get_device_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash->mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash->mock, flash->base.get_sector_size, flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash->mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash->mock, flash->base.read, flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash->mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (tpm, &flash->base, 0x10000, 33);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Helper function to release mock instances

 * @param test The test framework
 * @param tpm TPM to release
 * @param flash The flash device mock to release
 */
static void complete_tpm_mock_test (CuTest *test, struct tpm *tpm, struct flash_mock *flash)
{
	int status;

	status = flash_mock_validate_and_release (flash);
	CuAssertIntEquals (test, 0, status);

	tpm_release (tpm);
}

/*******************
 * Test cases
 *******************/

static void tpm_test_init (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear (CuTest *test)
{
	struct tpm_header header = {0};
	struct tpm_header new_header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.clear = 1;
	new_header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);

	status |= flash_mock_expect_erase_flash_sector (&flash, 0x10000, 
		sector_size + 33 * TPM_STORAGE_SEGMENT_SIZE);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&new_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear_erase_fail (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.clear = 1;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY, 
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear_write_fail (CuTest *test)
{
	struct tpm_header header = {0};
	struct tpm_header new_header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.clear = 1;
	new_header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);

	status |= flash_mock_expect_erase_flash_sector (&flash, 0x10000, 
		sector_size + 33 * TPM_STORAGE_SEGMENT_SIZE);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, FLASH_NO_MEMORY,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&new_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_clear_incomplete_write (CuTest *test)
{
	struct tpm_header header = {0};
	struct tpm_header new_header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.clear = 1;
	new_header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);

	status |= flash_mock_expect_erase_flash_sector (&flash, 0x10000, 
		sector_size + 33 * TPM_STORAGE_SEGMENT_SIZE);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header) - 1,
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&new_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, FLASH_UTIL_INCOMPLETE_WRITE, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_end_of_flash (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x16000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_end_of_flash_sector_aligned (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x15000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 32);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_non_4k_sector_size (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 512;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10200),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10200, 33);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_non_4k_sector_size_end_of_flash (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 512;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x3bc00),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x3bc00, 33);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_get_device_size_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, FLASH_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_get_sector_size_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_unaligned_address (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	uint32_t flash_size = 0x40000;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10001, 33);
	CuAssertIntEquals (test, TPM_STORAGE_NOT_ALIGNED, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_insufficient_flash (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	uint32_t flash_size = 0x16000 - 1;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, TPM_INSUFFICIENT_STORAGE, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_invalid_header (CuTest *test)
{
	struct tpm_header header = {0};
	struct tpm_header good_header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	good_header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS ((uint8_t*) &good_header,
		sizeof (struct tpm_header)), MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_invalid_header_write_fail (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_init_invalid_arg (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	status = tpm_init (NULL, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	status = tpm_init (&tpm, NULL, 0x10000, 33);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);
}

static void tpm_test_init_read_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_release_null (CuTest *test)
{
	TEST_START;

	tpm_release (NULL);
}

static void tpm_test_get_counter (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.nv_counter = 0xAA;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_get_counter (&tpm, &counter);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xAA, counter);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_counter_invalid_storage (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &header,
		sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_get_counter (&tpm, &counter);
	CuAssertIntEquals (test, TPM_INVALID_STORAGE, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_counter_invalid_arg (CuTest *test)
{
	struct flash_mock flash;
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

static void tpm_test_get_counter_read_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint64_t counter;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_get_counter (&tpm, &counter);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter (CuTest *test)
{
	struct tpm_header header = {0};
	struct tpm_header incremented_header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	incremented_header.magic = TPM_MAGIC;
	incremented_header.nv_counter = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&incremented_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_invalid_storage (CuTest *test)
{
	struct tpm_header header = {0};
	struct tpm_header incremented_header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.nv_counter = 3;
	incremented_header.magic = TPM_MAGIC;
	incremented_header.nv_counter = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&incremented_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_invalid_arg (CuTest *test)
{
	struct flash_mock flash;
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
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_increment_counter_write_fail (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tpm_increment_counter (&tpm);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE] = {0};
	uint8_t buffer[4096] = {0};
	uint8_t buffer_updated[4096] = {0};
	int status;

	TEST_START;

	storage[0] = 0xAA;
	storage[10] = 0xBB;
	storage[100] = 0xCC;
	storage[500] = 0xDD;
	storage[502] = 0xEE;
	storage[504] = 0xFF;
	storage[506] = 0x11;
	storage[508] = 0x22;
	storage[510] = 0x33;
	storage[511] = 0x44;

	buffer[2000] = 0xAB;
	buffer_updated[2000] = 0xAB;

	memcpy (&buffer_updated[6 * TPM_STORAGE_SEGMENT_SIZE], storage, TPM_STORAGE_SEGMENT_SIZE);

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + 2 * sector_size), MOCK_ARG_NOT_NULL, MOCK_ARG (sector_size));
	status |= mock_expect_output (&flash.mock, 1, buffer, sector_size, 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0,
		MOCK_ARG (0x10000 + 2 * sector_size));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sector_size,
		MOCK_ARG (0x10000 + 2 * sector_size), MOCK_ARG_PTR_CONTAINS (buffer_updated,
		sector_size), MOCK_ARG (sector_size));
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 14, storage, sizeof (storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_segment_as_big_as_sector (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 512;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE] = {0};
	int status;

	TEST_START;

	storage[0] = 0xAA;
	storage[10] = 0xBB;
	storage[100] = 0xCC;
	storage[500] = 0xDD;
	storage[502] = 0xEE;
	storage[504] = 0xFF;
	storage[506] = 0x11;
	storage[508] = 0x22;
	storage[510] = 0x33;
	storage[511] = 0x44;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0,
		MOCK_ARG (0x10000 + sector_size * 15));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (storage),
		MOCK_ARG (0x10000 + sector_size * 15), MOCK_ARG_PTR_CONTAINS (storage, sizeof (storage)),
		MOCK_ARG (sizeof (storage)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 14, storage, sizeof (storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_segment_as_big_as_sector_write_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 512;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE] = {0};
	int status;

	TEST_START;

	storage[0] = 0xAA;
	storage[10] = 0xBB;
	storage[100] = 0xCC;
	storage[500] = 0xDD;
	storage[502] = 0xEE;
	storage[504] = 0xFF;
	storage[506] = 0x11;
	storage[508] = 0x22;
	storage[510] = 0x33;
	storage[511] = 0x44;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 14, storage, sizeof (storage));
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_invalid_arg (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_set_storage (NULL, 0, storage, sizeof (storage));
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	status = tpm_set_storage (&tpm, 0, NULL, sizeof (storage));
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_invalid_len (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_set_storage (&tpm, 0, storage, sizeof (storage) + 1);
	CuAssertIntEquals (test, TPM_INVALID_LEN, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_out_of_range (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_set_storage (&tpm, tpm.num_segments + 1, storage, sizeof (storage));
	CuAssertIntEquals (test, TPM_OUT_OF_RANGE, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_get_sector_size_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE] = {0};
	int status;

	TEST_START;

	storage[0] = 0xAA;
	storage[10] = 0xBB;
	storage[100] = 0xCC;
	storage[500] = 0xDD;
	storage[502] = 0xEE;
	storage[504] = 0xFF;
	storage[506] = 0x11;
	storage[508] = 0x22;
	storage[510] = 0x33;
	storage[511] = 0x44;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 14, storage, sizeof (storage));
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_segment_bigger_than_sector (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 256;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE] = {0};
	int status;

	TEST_START;

	storage[0] = 0xAA;
	storage[10] = 0xBB;
	storage[100] = 0xCC;
	storage[500] = 0xDD;
	storage[502] = 0xEE;
	storage[504] = 0xFF;
	storage[506] = 0x11;
	storage[508] = 0x22;
	storage[510] = 0x33;
	storage[511] = 0x44;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 14, storage, sizeof (storage));
	CuAssertIntEquals (test, TPM_INVALID_LEN, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_read_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE] = {0};
	int status;

	TEST_START;

	storage[0] = 0xAA;
	storage[10] = 0xBB;
	storage[100] = 0xCC;
	storage[500] = 0xDD;
	storage[502] = 0xEE;
	storage[504] = 0xFF;
	storage[506] = 0x11;
	storage[508] = 0x22;
	storage[510] = 0x33;
	storage[511] = 0x44;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_NO_MEMORY,
		MOCK_ARG (0x10000 + 2 * sector_size), MOCK_ARG_NOT_NULL, MOCK_ARG (sector_size));
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 14, storage, sizeof (storage));
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_set_storage_write_fail (CuTest *test)
{
	uint8_t buffer[4096] = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE] = {0};
	int status;

	TEST_START;

	storage[0] = 0xAA;
	storage[10] = 0xBB;
	storage[100] = 0xCC;
	storage[500] = 0xDD;
	storage[502] = 0xEE;
	storage[504] = 0xFF;
	storage[506] = 0x11;
	storage[508] = 0x22;
	storage[510] = 0x33;
	storage[511] = 0x44;

	buffer[2000] = 0xAB;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + 2 * sector_size), MOCK_ARG_NOT_NULL, MOCK_ARG (sector_size));
	status |= mock_expect_output (&flash.mock, 1, buffer, sector_size, 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, FLASH_NO_MEMORY,
		MOCK_ARG (0x10000 + 2 * sector_size));
	CuAssertIntEquals (test, 0, status);

	status = tpm_set_storage (&tpm, 14, storage, sizeof (storage));
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	uint8_t exp_storage[TPM_STORAGE_SEGMENT_SIZE] = {0};
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	exp_storage[0] = 0xAA;
	exp_storage[10] = 0xBB;
	exp_storage[100] = 0xCC;
	exp_storage[500] = 0xDD;
	exp_storage[502] = 0xEE;
	exp_storage[504] = 0xFF;
	exp_storage[506] = 0x11;
	exp_storage[508] = 0x22;
	exp_storage[510] = 0x33;
	exp_storage[511] = 0x44;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0,
		MOCK_ARG (0x10000 + sector_size), MOCK_ARG_NOT_NULL, MOCK_ARG (TPM_STORAGE_SEGMENT_SIZE));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &exp_storage,
		TPM_STORAGE_SEGMENT_SIZE, 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage));
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (exp_storage, storage, sizeof (exp_storage));
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_invalid_arg (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_get_storage (NULL, 0, storage, sizeof (storage));
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	status = tpm_get_storage (&tpm, 0, NULL, sizeof (storage));
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);
	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_invalid_len (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_get_storage (&tpm, 0, storage, 0);
	CuAssertIntEquals (test, TPM_INVALID_LEN, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_out_of_range (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_get_storage (&tpm, tpm.num_segments + 1, storage, sizeof (storage));
	CuAssertIntEquals (test, TPM_OUT_OF_RANGE, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_get_sector_size_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY,
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage));
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_get_storage_read_storage_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	uint8_t storage[TPM_STORAGE_SEGMENT_SIZE];
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, FLASH_NO_MEMORY,
		MOCK_ARG (0x10000 + sector_size), MOCK_ARG_NOT_NULL,
		MOCK_ARG (TPM_STORAGE_SEGMENT_SIZE));
	CuAssertIntEquals (test, 0, status);

	status = tpm_get_storage (&tpm, 0, storage, sizeof (storage));
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	struct tpm_header header = {0};
	struct tpm_header new_header = {0};
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.clear = 1;
	new_header.magic = TPM_MAGIC;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= flash_mock_expect_erase_flash_sector (&flash, 0x10000, 
		sector_size + 33 * TPM_STORAGE_SEGMENT_SIZE);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&new_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_not_scheduled (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	struct tpm_header header = {0};
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.clear = 0;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_invalid_storage (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	struct tpm_header header = {0};
	struct tpm_header new_header = {0};
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	new_header.magic = TPM_MAGIC;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= flash_mock_expect_erase_flash_sector (&flash, 0x10000, 
		sector_size + 33 * TPM_STORAGE_SEGMENT_SIZE);

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&new_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_segment_as_big_as_sector (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	struct tpm_header header = {0};
	struct tpm_header new_header = {0};
	uint32_t flash_size = 0x40000;
	uint32_t sector_size = TPM_STORAGE_SEGMENT_SIZE;
	int i_sector;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.clear = 1;
	new_header.magic = TPM_MAGIC;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_device_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &flash_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, (uint8_t*) &sector_size, sizeof (uint32_t), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, (uint8_t*) &new_header,
		sizeof (struct tpm_header), 2);

	CuAssertIntEquals (test, 0, status);

	status = tpm_init (&tpm, &flash.base, 0x10000, 33);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash.mock);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);
	
	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	for (i_sector = 0; i_sector < 34; ++i_sector) {
		status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, 
			MOCK_ARG (0x10000 + i_sector * sector_size));
	}

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&new_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_read_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_erase_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	struct tpm_header header = {0};
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY, 
		MOCK_ARG_NOT_NULL);

	CuAssertIntEquals (test, 0, status);

	tpm.observer.on_soft_reset (&tpm.observer);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_on_soft_reset_null (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	tpm.observer.on_soft_reset (NULL);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear (CuTest *test)
{
	struct tpm_header header = {0};
	struct tpm_header new_header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	new_header.magic = TPM_MAGIC;
	new_header.clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&new_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_already_scheduled (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;
	header.clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);
	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_invalid_storage (CuTest *test)
{
	struct tpm_header header = {0};
	struct tpm_header new_header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	uint32_t sector_size = 4096;
	int status;

	TEST_START;

	header.clear = 1;
	new_header.magic = TPM_MAGIC;
	new_header.clear = 1;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &sector_size, sizeof (sector_size), -1);

	status |= mock_expect (&flash.mock, flash.base.sector_erase, &flash, 0, MOCK_ARG (0x10000));

	status |= mock_expect (&flash.mock, flash.base.write, &flash, sizeof (struct tpm_header),
		MOCK_ARG (0x10000), MOCK_ARG_PTR_CONTAINS (&new_header, sizeof (struct tpm_header)),
		MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, 0, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_read_fail (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, FLASH_NO_MEMORY, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_write_fail (CuTest *test)
{
	struct tpm_header header = {0};
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	header.magic = TPM_MAGIC;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG (sizeof (struct tpm_header)));
	status |= mock_expect_output (&flash.mock, 1, &header, sizeof (struct tpm_header), 2);

	status |= mock_expect (&flash.mock, flash.base.get_sector_size, &flash, FLASH_NO_MEMORY, 
		MOCK_ARG_NOT_NULL);
	CuAssertIntEquals (test, 0, status);

	status = tpm_schedule_clear (&tpm);
	CuAssertIntEquals (test, FLASH_NO_MEMORY, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

static void tpm_test_schedule_clear_null (CuTest *test)
{
	struct flash_mock flash;
	struct tpm tpm;
	int status;

	TEST_START;

	setup_tpm_mock_test (test, &tpm, &flash);

	status = tpm_schedule_clear (NULL);
	CuAssertIntEquals (test, TPM_INVALID_ARGUMENT, status);

	complete_tpm_mock_test (test, &tpm, &flash);
}

CuSuite* get_tpm_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, tpm_test_init);
	SUITE_ADD_TEST (suite, tpm_test_init_clear);
	SUITE_ADD_TEST (suite, tpm_test_init_clear_erase_fail);
	SUITE_ADD_TEST (suite, tpm_test_init_clear_write_fail);
	SUITE_ADD_TEST (suite, tpm_test_init_clear_incomplete_write);
	SUITE_ADD_TEST (suite, tpm_test_init_end_of_flash);
	SUITE_ADD_TEST (suite, tpm_test_init_end_of_flash_sector_aligned);
	SUITE_ADD_TEST (suite, tpm_test_init_non_4k_sector_size);
	SUITE_ADD_TEST (suite, tpm_test_init_non_4k_sector_size_end_of_flash);
	SUITE_ADD_TEST (suite, tpm_test_init_get_device_size_fail);
	SUITE_ADD_TEST (suite, tpm_test_init_get_sector_size_fail);
	SUITE_ADD_TEST (suite, tpm_test_init_unaligned_address);
	SUITE_ADD_TEST (suite, tpm_test_init_insufficient_flash);
	SUITE_ADD_TEST (suite, tpm_test_init_invalid_header);
	SUITE_ADD_TEST (suite, tpm_test_init_invalid_header_write_fail);
	SUITE_ADD_TEST (suite, tpm_test_init_invalid_arg);
	SUITE_ADD_TEST (suite, tpm_test_init_read_fail);
	SUITE_ADD_TEST (suite, tpm_test_release_null);
	SUITE_ADD_TEST (suite, tpm_test_get_counter);
	SUITE_ADD_TEST (suite, tpm_test_get_counter_invalid_storage);
	SUITE_ADD_TEST (suite, tpm_test_get_counter_invalid_arg);
	SUITE_ADD_TEST (suite, tpm_test_get_counter_read_fail);
	SUITE_ADD_TEST (suite, tpm_test_increment_counter);
	SUITE_ADD_TEST (suite, tpm_test_increment_counter_invalid_storage);
	SUITE_ADD_TEST (suite, tpm_test_increment_counter_invalid_arg);
	SUITE_ADD_TEST (suite, tpm_test_increment_counter_read_fail);
	SUITE_ADD_TEST (suite, tpm_test_increment_counter_write_fail);
	SUITE_ADD_TEST (suite, tpm_test_set_storage);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_segment_as_big_as_sector);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_segment_as_big_as_sector_write_fail);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_invalid_arg);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_invalid_len);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_out_of_range);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_get_sector_size_fail);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_segment_bigger_than_sector);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_read_fail);
	SUITE_ADD_TEST (suite, tpm_test_set_storage_write_fail);
	SUITE_ADD_TEST (suite, tpm_test_get_storage);
	SUITE_ADD_TEST (suite, tpm_test_get_storage_invalid_arg);
	SUITE_ADD_TEST (suite, tpm_test_get_storage_invalid_len);
	SUITE_ADD_TEST (suite, tpm_test_get_storage_out_of_range);
	SUITE_ADD_TEST (suite, tpm_test_get_storage_get_sector_size_fail);
	SUITE_ADD_TEST (suite, tpm_test_get_storage_read_storage_fail);
	SUITE_ADD_TEST (suite, tpm_test_on_soft_reset);
	SUITE_ADD_TEST (suite, tpm_test_on_soft_reset_not_scheduled);
	SUITE_ADD_TEST (suite, tpm_test_on_soft_reset_invalid_storage);
	SUITE_ADD_TEST (suite, tpm_test_on_soft_reset_segment_as_big_as_sector);
	SUITE_ADD_TEST (suite, tpm_test_on_soft_reset_read_fail);
	SUITE_ADD_TEST (suite, tpm_test_on_soft_reset_erase_fail);
	SUITE_ADD_TEST (suite, tpm_test_on_soft_reset_null);
	SUITE_ADD_TEST (suite, tpm_test_schedule_clear);
	SUITE_ADD_TEST (suite, tpm_test_schedule_clear_already_scheduled);
	SUITE_ADD_TEST (suite, tpm_test_schedule_clear_invalid_storage);
	SUITE_ADD_TEST (suite, tpm_test_schedule_clear_read_fail);
	SUITE_ADD_TEST (suite, tpm_test_schedule_clear_write_fail);
	SUITE_ADD_TEST (suite, tpm_test_schedule_clear_null);

	return suite;
}
