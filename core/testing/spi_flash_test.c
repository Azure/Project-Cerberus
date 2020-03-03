// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/spi_flash.h"
#include "flash/spi_flash_sfdp.h"
#include "flash/flash_common.h"
#include "mock/flash_master_mock.h"


static const char *SUITE = "spi_flash";


/**
 * Initialize the SFDP interface for property discovery.
 *
 * @param test The test framework.
 * @param sfdp The SFDP interface to initialize.
 * @param flash The flash mock to set the expectations on.
 * @param header The header data to return.
 */
static void spi_flash_testing_init_sfdp (CuTest *test, struct spi_flash_sfdp *sfdp,
	struct flash_master_mock *flash, uint32_t *header)
{
	int status;
	int header_length = sizeof (uint32_t) * 4;

	status = flash_master_mock_expect_rx_xfer (flash, 0, (uint8_t*) header, header_length,
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, header_length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (sfdp, &flash->base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash->mock);
	CuAssertIntEquals (test, 0, status);
}

/*******************
 * Test cases
 *******************/

static void spi_flash_test_init (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, flash.base.get_device_size);
	CuAssertPtrNotNull (test, flash.base.read);
	CuAssertPtrNotNull (test, flash.base.get_page_size);
	CuAssertPtrNotNull (test, flash.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, flash.base.write);
	CuAssertPtrNotNull (test, flash.base.get_sector_size);
	CuAssertPtrNotNull (test, flash.base.sector_erase);
	CuAssertPtrNotNull (test, flash.base.get_block_size);
	CuAssertPtrNotNull (test, flash.base.block_erase);
	CuAssertPtrNotNull (test, flash.base.chip_erase);

	CuAssertPtrEquals (test, spi_flash_get_device_size, flash.base.get_device_size);
	CuAssertPtrEquals (test, spi_flash_read, flash.base.read);
	CuAssertPtrEquals (test, spi_flash_get_page_size, flash.base.get_page_size);
	CuAssertPtrEquals (test, spi_flash_minimum_write_per_page, flash.base.minimum_write_per_page);
	CuAssertPtrEquals (test, spi_flash_write, flash.base.write);
	CuAssertPtrEquals (test, spi_flash_get_sector_size, flash.base.get_sector_size);
	CuAssertPtrEquals (test, spi_flash_sector_erase, flash.base.sector_erase);
	CuAssertPtrEquals (test, spi_flash_get_block_size, flash.base.get_block_size);
	CuAssertPtrEquals (test, spi_flash_block_erase, flash.base.block_erase);
	CuAssertPtrEquals (test, spi_flash_chip_erase, flash.base.chip_erase);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_init_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (NULL, &mock.base);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_init (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_init_fast_read (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, flash.base.get_device_size);
	CuAssertPtrNotNull (test, flash.base.read);
	CuAssertPtrNotNull (test, flash.base.get_page_size);
	CuAssertPtrNotNull (test, flash.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, flash.base.write);
	CuAssertPtrNotNull (test, flash.base.get_sector_size);
	CuAssertPtrNotNull (test, flash.base.sector_erase);
	CuAssertPtrNotNull (test, flash.base.get_block_size);
	CuAssertPtrNotNull (test, flash.base.block_erase);
	CuAssertPtrNotNull (test, flash.base.chip_erase);

	CuAssertPtrEquals (test, spi_flash_get_device_size, flash.base.get_device_size);
	CuAssertPtrEquals (test, spi_flash_read, flash.base.read);
	CuAssertPtrEquals (test, spi_flash_get_page_size, flash.base.get_page_size);
	CuAssertPtrEquals (test, spi_flash_minimum_write_per_page, flash.base.minimum_write_per_page);
	CuAssertPtrEquals (test, spi_flash_write, flash.base.write);
	CuAssertPtrEquals (test, spi_flash_get_sector_size, flash.base.get_sector_size);
	CuAssertPtrEquals (test, spi_flash_sector_erase, flash.base.sector_erase);
	CuAssertPtrEquals (test, spi_flash_get_block_size, flash.base.get_block_size);
	CuAssertPtrEquals (test, spi_flash_block_erase, flash.base.block_erase);
	CuAssertPtrEquals (test, spi_flash_chip_erase, flash.base.chip_erase);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_init_fast_read_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (NULL, &mock.base);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_init_fast_read (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_release_null (CuTest *test)
{
	TEST_START;

	spi_flash_release (NULL);
}

static void spi_flash_test_release_no_init (CuTest *test)
{
	struct spi_flash flash;

	TEST_START;

	memset (&flash, 0, sizeof (flash));

	spi_flash_release (&flash);
}

static void spi_flash_test_set_device_size (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t dev_size = 0x100000;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, dev_size);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, dev_size, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_set_device_size_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (NULL, 0x100000);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_size_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t dev_size = 0x100000;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, dev_size);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.get_device_size (&flash.base, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, dev_size, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_size_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (NULL, &out);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_get_device_size (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read_max_address (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0xffffff, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0xffffff, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x13, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read_fast_read (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x0b, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read_fast_read_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x0c, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = flash.base.read (&flash.base, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data_in[4];
	size_t length = sizeof (data_in);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (NULL, 0x1234, data_in, length);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_read (&flash, 0x1234, NULL, length);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_read_out_of_range (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data_in[4];
	size_t length = sizeof (data_in);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1000000, data_in, length);
	CuAssertIntEquals (test, SPI_FLASH_ADDRESS_OUT_OF_RANGE, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_read_too_long (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data_in[4];
	size_t length = sizeof (data_in);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0xfffffd, data_in, length);
	CuAssertIntEquals (test, SPI_FLASH_OPERATION_OUT_OF_RANGE, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_read_error_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 4;
	uint8_t data_in[length];
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read_status_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 4;
	uint8_t data_in[length];

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 4;
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_across_page (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	uint8_t cmd_expected[] = {0x01};
	uint8_t cmd2_expected[] = {0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x12ff, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1300, 0, cmd2_expected, sizeof (cmd2_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x12ff, data, sizeof (data));
	CuAssertIntEquals (test, sizeof (data), status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_write_multiple_pages (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[FLASH_PAGE_SIZE * 2];
	uint8_t page1_expected[FLASH_PAGE_SIZE];
	uint8_t page2_expected[FLASH_PAGE_SIZE];
	uint8_t read_status = 0;
	int i;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < FLASH_PAGE_SIZE; i++) {
		data[i] = i;
		page1_expected[i] = i;
	}
	for (i = FLASH_PAGE_SIZE - 1; i >= 0; i--) {
		data[FLASH_PAGE_SIZE + i] = i;
		page2_expected[i] = i;
	}

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1200, 0, page1_expected, sizeof (page1_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1300, 0, page2_expected, sizeof (page2_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1200, data, sizeof (data));
	CuAssertIntEquals (test, sizeof (data), status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_write_multiple_pages_not_aligned (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[FLASH_PAGE_SIZE * 2];
	uint8_t page1_expected[0x10] = {0x02, 0x00, 0x12, 0xf0};
	uint8_t page2_expected[FLASH_PAGE_SIZE] = {0x02, 0x00, 0x13, 0x00};
	uint8_t page3_expected[FLASH_PAGE_SIZE - 0x10] = {0x02, 0x00, 0x14, 0x00};
	uint8_t read_status = 0;
	int i;
	uint8_t *pos;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	for (i = 0; i < FLASH_PAGE_SIZE; i++) {
		data[i] = i;
	}
	for (i = FLASH_PAGE_SIZE - 1; i >= 0; i--) {
		data[FLASH_PAGE_SIZE + i] = i;
	}

	pos = data;
	for (i = 0; i < 0x10; i++, pos++) {
		page1_expected[i] = *pos;
	}
	for (i = 0; i < FLASH_PAGE_SIZE; i++, pos++) {
		page2_expected[i] = *pos;
	}
	for (i = 0; i < FLASH_PAGE_SIZE - 0x10; i++, pos++) {
		page3_expected[i] = *pos;
	}

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x12f0, 0, page1_expected, sizeof (page1_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1300, 0, page2_expected, sizeof (page2_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1400, 0, page3_expected, sizeof (page3_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x12f0, data, sizeof (data));
	CuAssertIntEquals (test, sizeof (data), status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_write_max_address (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0xffffff, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0xffffff, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = flash.base.write (&flash.base, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (NULL, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_write (&flash, 0x1234, NULL, sizeof (cmd_expected));
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_write_out_of_range (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1000000, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, SPI_FLASH_ADDRESS_OUT_OF_RANGE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_too_long (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0xfffffd, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, SPI_FLASH_OPERATION_OUT_OF_RANGE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_error_enable (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_error_write (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_CMD (0x02, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_error_second_page (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	uint8_t cmd_expected[] = {0x01};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x12ff, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x12ff, data, sizeof (data));
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_error_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_status_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0x20, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_offset_address (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0x20, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1200);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_max_address (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0x20, 0xfff000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0xffffff);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0x20, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = flash.base.sector_erase (&flash.base, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (NULL, 0x1000);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_out_of_range (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000000);
	CuAssertIntEquals (test, SPI_FLASH_ADDRESS_OUT_OF_RANGE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_error_enable (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_error_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_status_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_ERASE_CMD (0x20, 0x1000));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_wait_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0x20, 0x1000));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0xd8, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_offset_address (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0xd8, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x12000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_max_address (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0xd8, 0xff0000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0xffffff);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0xd8, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = flash.base.block_erase (&flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (NULL, 0x10000);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_out_of_range (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x1000000);
	CuAssertIntEquals (test, SPI_FLASH_ADDRESS_OUT_OF_RANGE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_error_enable (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_error_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_status_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_ERASE_CMD (0xd8, 0x10000));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_wait_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0xd8, 0x10000));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xc7));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xc7));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = flash.base.chip_erase (&flash.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_error_enable (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_error_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (&flash);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_status_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xc7));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_wait_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xc7));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_write_in_progress (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_no_write_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_write_in_progress (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_write_in_progress_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_write_in_progress (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_in_progress_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_is_write_in_progress (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_wait_for_write (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_wait_for_write (&flash, 100);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_wait_for_write_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_wait_for_write (NULL, 100);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_wait_for_write_timeout (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_wait_for_write (&flash, 35);
	CuAssertIntEquals (test, SPI_FLASH_WIP_TIMEOUT, status);
	CuAssertTrue (test, ((mock.mock.call_count >= 3) && (mock.mock.call_count <= 5)));

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_wait_for_write_immediate_timeout (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_wait_for_write (&flash, 0);
	CuAssertIntEquals (test, SPI_FLASH_WIP_TIMEOUT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_wait_for_write_no_timeout (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_wait_for_write (&flash, -1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_wait_for_write_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, FLASH_MASTER_XFER_FAILED, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_wait_for_write (&flash, 100);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x11, vendor);
	CuAssertIntEquals (test, 0x2233, device);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_twice (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x11, vendor);
	CuAssertIntEquals (test, 0x2233, device);

	vendor = 0;
	device = 0;

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x11, vendor);
	CuAssertIntEquals (test, 0x2233, device);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_read_ff (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t error[] = {0xff, 0xff, 0xff};
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, error, length,
		FLASH_EXP_READ_REG (0x9f, length));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff, vendor);
	CuAssertIntEquals (test, 0xffff, device);

	vendor = 0;
	device = 0;

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x11, vendor);
	CuAssertIntEquals (test, 0x2233, device);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_read_00 (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t error[] = {0x00, 0x00, 0x00};
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, error, length,
		FLASH_EXP_READ_REG (0x9f, length));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, vendor);
	CuAssertIntEquals (test, 0, device);

	vendor = 0;
	device = 0;

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x11, vendor);
	CuAssertIntEquals (test, 0x2233, device);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (NULL, &vendor, &device);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_only_vendor (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint8_t vendor;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash, &vendor, NULL);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x11, vendor);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_only_device (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash, NULL, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x2233, device);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 3;
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_read_after_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, FLASH_MASTER_XFER_FAILED, data, length,
		FLASH_EXP_READ_REG (0x9f, length));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	vendor = 1;
	device = 2;

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);
	CuAssertIntEquals (test, 1, vendor);
	CuAssertIntEquals (test, 2, device);

	vendor = 0;
	device = 0;

	status = spi_flash_get_device_id (&flash, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0x11, vendor);
	CuAssertIntEquals (test, 0x2233, device);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_reset_device (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_reset_device_error_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_status_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_error_enable (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0x66));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_error_resetting (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_4byte_address_mode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_4byte_address_mode_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_enable_4byte_address_mode (NULL, 1);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_enable_4byte_address_mode_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xb7));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_disable_4byte_address_mode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xe9));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_disable_4byte_address_mode_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xe9));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_16M (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_32M (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x2000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_is_4byte_address_mode (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_4byte_address_read (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x03, 0x123456, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x123456, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_4byte_address_write (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x02, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, 4, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_4byte_address_sector_erase (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x20, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_4byte_address_block_erase (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xd8, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_macronix (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);
	uint8_t enable_expected[] = {0x40};
	uint8_t disable_expected[] = {0x00};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_winbond (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t enable_expected[] = {0x02};
	uint8_t disable_expected[] = {0x00};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x31, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x31, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_spansion (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t spansion[] = {0x01, 0x02, 0x17};
	const size_t length = sizeof (spansion);
	uint8_t enable_expected[] = {0x02};
	uint8_t disable_expected[] = {0x00};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, spansion, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x71, 0x800002, 0, &enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x71, 0x800002, 0, &disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_unknown (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t unknown[] = {0x11, 0x20, 0x19};
	const size_t length = sizeof (unknown);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, unknown, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_DEVICE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_enable_quad_spi (NULL, 1);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_enable_quad_spi_error_id (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_error_read_status (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_error_write_enable (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_error_write_reg (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);
	uint8_t cmd_expected[] = {0x40};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_REG (0x01, cmd_expected, sizeof (cmd_expected)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_error_wait_write (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);
	uint8_t cmd_expected[] = {0x40};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_error_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_STATUS_WIP;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_spansion_error_read_status (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t spansion[] = {0x01, 0x02, 0x17};
	const size_t length = sizeof (spansion);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, spansion, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_spansion_error_write_enable (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t spansion[] = {0x01, 0x02, 0x17};
	const size_t length = sizeof (spansion);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, spansion, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_spansion_error_write_reg (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t spansion[] = {0x01, 0x02, 0x17};
	const size_t length = sizeof (spansion);
	uint8_t enable_expected[] = {0x02};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, spansion, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_CMD (0x71, 0x800002, 0, &enable_expected, sizeof (enable_expected)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_spansion_error_wait_write (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t spansion[] = {0x01, 0x02, 0x17};
	const size_t length = sizeof (spansion);
	uint8_t enable_expected[] = {0x02};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, spansion, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x71, 0x800002, 0, &enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_spansion_error_in_progress (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_STATUS_WIP;
	uint8_t spansion[] = {0x01, 0x02, 0x17};
	const size_t length = sizeof (spansion);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, spansion, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_macronix (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);
	uint8_t enable_expected[] = {0x40};
	uint8_t disable_expected[] = {0x00};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, enable_expected, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, disable_expected, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_winbond (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t enable_expected[] = {0x02};
	uint8_t disable_expected[] = {0x00};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, enable_expected, 1,
		FLASH_EXP_READ_REG (0x35, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, disable_expected, 1,
		FLASH_EXP_READ_REG (0x35, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_spansion (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t spansion[] = {0x01, 0x02, 0x17};
	const size_t length = sizeof (spansion);
	uint8_t enable_expected[] = {0x02};
	uint8_t disable_expected[] = {0x00};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, spansion, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, enable_expected, 1,
		FLASH_EXP_READ_CMD (0x65, 0x800002, 1, -1, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, disable_expected, 1,
		FLASH_EXP_READ_CMD (0x65, 0x800002, 1, -1, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_unknown (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t unknown[] = {0x11, 0x20, 0x19};
	const size_t length = sizeof (unknown);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, unknown, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_DEVICE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_is_quad_spi_enabled (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_is_quad_spi_enabled_error_id (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_error_read_reg (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_clear_block_protect (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect_already_clear (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0x40;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_clear_block_protect (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_clear_block_protect (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_clear_block_protect_error_read (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_clear_block_protect (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect_error_write (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0x7c;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_clear_block_protect (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_deep_power_down_enter (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb9));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_deep_power_down_release (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_deep_power_down_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_deep_power_down (NULL, 1);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_deep_power_down_enter_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xb9));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash, 1);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_deep_power_down_release_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xab));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_force_4byte_address_mode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_force_4byte_address_mode (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_force_4byte_address_mode_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (NULL, 1);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_macronix (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);
	uint8_t enable_expected[] = {0x20};
	uint8_t disable_expected[] = {~0x20};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, enable_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, disable_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_winbond (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t enable_expected[] = {0x01};
	uint8_t disable_expected[] = {~0x01};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, enable_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, disable_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_unknown (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t unknown[] = {0x11, 0x20, 0x19};
	const size_t length = sizeof (unknown);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, unknown, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_DEVICE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_error_id (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_error_read_reg_macronix (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_error_read_reg_winbond (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_3byte_only_incompatible_spi (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_INCOMPATIBLE_SPI_MASTER, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x0fffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (32 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_3byte_4byte_incompatible_spi (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x0fffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, FLASH_CAP_3BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_INCOMPATIBLE_SPI_MASTER, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_INCOMPATIBLE_SPI_MASTER, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x0fffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (32 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_4byte_only_incompatible_spi (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x0fffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, FLASH_CAP_3BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_INCOMPATIBLE_SPI_MASTER, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = spi_flash_discover_device_properties (NULL, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_discover_device_properties (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_sfdp_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, 36));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_large_device (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x80000022,
		0x6b08eb44,
		0xbb043b08,
		0xfffffffe,
		0xff00ffff,
		0xeb44ffff,
		0x520f200c,
		0xff00d810
	};
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_LARGE_DEVICE, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0, out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_4byte_address_mode_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, true);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_4byte_address_mode_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xe9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_4byte_address_mode_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_enable_4byte_address_mode (&flash, false);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_enable_4byte_address_mode (&flash, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);
	uint8_t enable_expected[] = {0x20};
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, enable_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_detect_4byte_address_mode_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x0fffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_force_4byte_address_mode_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash, true);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_force_4byte_address_mode_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_force_4byte_address_mode (&flash, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_force_4byte_address_mode_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_force_4byte_address_mode (&flash, false);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_force_4byte_address_mode (&flash, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x13, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_fast_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x0b, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_fast_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x0c, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_fast_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x0b, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_write_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_write_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_write_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x02, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_sector_erase_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0x20, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_sector_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_sector_erase_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x20, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_block_erase_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0xd8, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_block_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_1_block_erase_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xd8, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_2_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8120e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_2_READ_CMD (0x3b, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_2_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8320e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_2_READ_4B_CMD (0x3c, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_2_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8520e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_2_READ_4B_CMD (0x3b, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_2_read_with_mode_bytes (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8120e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b8c,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_2_READ_CMD (0x3b, 0x1234, 1, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_2_read_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8120e5,
		0x00ffffff,
		0xff00ff00,
		0xff003a08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_2_READ_CMD (0x3a, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_2_write_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8320e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_2_sector_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8320e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_2_block_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8320e5,
		0x00ffffff,
		0xff00ff00,
		0xff003b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_2_2_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9120e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_2_2_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9320e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_4B_CMD (0xbc, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_2_2_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9520e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_4B_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_2_2_read_with_mode_bytes (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9120e5,
		0x00ffffff,
		0xff00ff00,
		0xbb443b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_CMD (0xbb, 0x1234, 0, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_2_2_read_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9120e5,
		0x00ffffff,
		0xff00ff00,
		0xba043b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_CMD (0xba, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_2_2_write_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9320e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_2_2_sector_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9320e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_2_2_block_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9320e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_2_2_2_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9120e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_2_2_2_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9320e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_4B_CMD (0xbc, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_2_2_2_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9520e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_4B_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_2_2_2_read_with_mode_bytes (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9120e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffef,
		0xbb44ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_2_2_2_read_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9120e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffef,
		0xba04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_2_2_2_write_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9320e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_2_2_2_sector_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9320e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_2_2_2_block_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9320e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_4_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_4_READ_CMD (0x6b, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_4_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd320e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_4_READ_4B_CMD (0x6c, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_4_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd520e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_4_READ_4B_CMD (0x6b, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_4_read_with_mode_bytes (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6b8cff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_4_READ_CMD (0x6b, 0x1234, 1, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_4_read_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6a08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_4_READ_CMD (0x6a, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_4_write_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd320e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_4_sector_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd320e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_1_4_block_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd320e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_4_4_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_4_4_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_4B_CMD (0xec, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_4_4_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff520e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_4B_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_4_4_read_without_mode_bytes (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb04,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_4_4_read_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08ea44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xea, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_4_4_write_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_4_4_sector_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_1_4_4_block_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_4_4_4_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_4_4_4_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_4B_CMD (0xec, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_4_4_4_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff520e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_4B_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_4_4_4_read_without_mode_bytes (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb04ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_4_4_4_read_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xea44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_4_4_4_write_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_4_4_4_sector_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_flash_4_4_4_block_erase_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_spi_1_1_1_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_spi_1_1_1_fast_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x0b, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_spi_1_1_2_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_2_READ_CMD (0x3b, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_spi_1_2_2_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_spi_2_2_2_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_spi_1_1_4_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_4_READ_CMD (0x6b, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_spi_1_4_4_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_spi_4_4_4_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffff,
		0xbb04ffff,
		0xeb44ffff,
		0xd810200c,
		0xff00ff00
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = testing_validate_array (data, data_in, length);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, flash.base.get_device_size);
	CuAssertPtrNotNull (test, flash.base.read);
	CuAssertPtrNotNull (test, flash.base.get_page_size);
	CuAssertPtrNotNull (test, flash.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, flash.base.write);
	CuAssertPtrNotNull (test, flash.base.get_sector_size);
	CuAssertPtrNotNull (test, flash.base.sector_erase);
	CuAssertPtrNotNull (test, flash.base.get_block_size);
	CuAssertPtrNotNull (test, flash.base.block_erase);
	CuAssertPtrNotNull (test, flash.base.chip_erase);

	CuAssertPtrEquals (test, spi_flash_get_device_size, flash.base.get_device_size);
	CuAssertPtrEquals (test, spi_flash_read, flash.base.read);
	CuAssertPtrEquals (test, spi_flash_get_page_size, flash.base.get_page_size);
	CuAssertPtrEquals (test, spi_flash_minimum_write_per_page, flash.base.minimum_write_per_page);
	CuAssertPtrEquals (test, spi_flash_write, flash.base.write);
	CuAssertPtrEquals (test, spi_flash_get_sector_size, flash.base.get_sector_size);
	CuAssertPtrEquals (test, spi_flash_sector_erase, flash.base.sector_erase);
	CuAssertPtrEquals (test, spi_flash_get_block_size, flash.base.get_block_size);
	CuAssertPtrEquals (test, spi_flash_block_erase, flash.base.block_erase);
	CuAssertPtrEquals (test, spi_flash_chip_erase, flash.base.chip_erase);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t enable_expected[] = {0x20};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, enable_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x13, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8420e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_4B_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_1_1_4_read_3byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_1_4_READ_CMD (0x6b, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_1_4_4_read_3byte_4byte (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t mode_expected[] = {0x20};
	uint8_t qspi_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, qspi_expected, sizeof (qspi_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_4B_CMD (0xec, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_1_2_2_read_4byte_only (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff9520e5,
		0x00ffffff,
		0xff00ff00,
		0xbb043b08,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_2_2_READ_4B_CMD (0xbb, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_fast_read (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, true, false, false, false);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, flash.base.get_device_size);
	CuAssertPtrNotNull (test, flash.base.read);
	CuAssertPtrNotNull (test, flash.base.get_page_size);
	CuAssertPtrNotNull (test, flash.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, flash.base.write);
	CuAssertPtrNotNull (test, flash.base.get_sector_size);
	CuAssertPtrNotNull (test, flash.base.sector_erase);
	CuAssertPtrNotNull (test, flash.base.get_block_size);
	CuAssertPtrNotNull (test, flash.base.block_erase);
	CuAssertPtrNotNull (test, flash.base.chip_erase);

	CuAssertPtrEquals (test, spi_flash_get_device_size, flash.base.get_device_size);
	CuAssertPtrEquals (test, spi_flash_read, flash.base.read);
	CuAssertPtrEquals (test, spi_flash_get_page_size, flash.base.get_page_size);
	CuAssertPtrEquals (test, spi_flash_minimum_write_per_page, flash.base.minimum_write_per_page);
	CuAssertPtrEquals (test, spi_flash_write, flash.base.write);
	CuAssertPtrEquals (test, spi_flash_get_sector_size, flash.base.get_sector_size);
	CuAssertPtrEquals (test, spi_flash_sector_erase, flash.base.sector_erase);
	CuAssertPtrEquals (test, spi_flash_get_block_size, flash.base.get_block_size);
	CuAssertPtrEquals (test, spi_flash_block_erase, flash.base.block_erase);
	CuAssertPtrEquals (test, spi_flash_chip_erase, flash.base.chip_erase);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x0b, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_wake_device (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Release deep power down. */
	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, true, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_reset_device (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Reset the device. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, true, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_drive_strength (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t id_length = sizeof (winbond);
	uint8_t initial = 0x00;
	uint8_t configured = 0x20;
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Configure output drive strength. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x11, &configured, sizeof (configured)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &configured, sizeof (configured),
		FLASH_EXP_READ_REG (0x15, sizeof (configured)));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, true, false, false, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x0b, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_wake_reset_and_drive_strength (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t id_length = sizeof (winbond);
	uint8_t initial = 0x00;
	uint8_t configured = 0x20;
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Release deep power down. */
	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Reset the device. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	/* Configure output drive strength. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x11, &configured, sizeof (configured)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &configured, sizeof (configured),
		FLASH_EXP_READ_REG (0x15, sizeof (configured)));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, true, true, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_wip_set (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint8_t wip_set = FLASH_STATUS_WIP;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x03, 0x1234, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_init_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (NULL, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_initialize_device (&flash, NULL, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_init_fast_read_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (NULL, &mock.base, true, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_initialize_device (&flash, NULL, true, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_wake_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Release deep power down. */
	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xab));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, true, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_id_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_wip_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t id_length = sizeof (winbond);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_reset_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t id_length = sizeof (winbond);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Reset the device. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, true, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_drive_strength_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t id_length = sizeof (winbond);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Configure output drive strength. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, true, false, false, true);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_sfdp_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, 16));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_parameters_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, 36));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_address_mode_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8220e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect address mode. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_qspi_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_clear_protect_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xff8020e5,
		0x00ffffff,
		0xff00ff00,
		0xff00ff00,
		0xffffffee,
		0xff00ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_id_ff (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t id[] = {0xff, 0xff, 0xff};
	const size_t id_length = sizeof (id);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, id, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_NO_DEVICE, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_id_00 (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t id[] = {0x00, 0x00, 0x00};
	const size_t id_length = sizeof (id);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, id, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_NO_DEVICE, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_save_device_info (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FLASH_DEVICE_INFO_VERSION, info.version);
	CuAssertIntEquals (test, 0x1000000, info.device_size);
	CuAssertIntEquals (test, 0, info.use_fast_read);
	CuAssertIntEquals (test, 0x03, info.read_opcode);
	CuAssertIntEquals (test, 0, info.read_dummy);
	CuAssertIntEquals (test, 0, info.read_mode);
	CuAssertIntEquals (test, 0, info.read_flags);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_initialized_device (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FLASH_DEVICE_INFO_VERSION, info.version);
	CuAssertIntEquals (test, 2 * 1024 * 1024, info.device_size);
	CuAssertIntEquals (test, FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR, info.capabilities);
	CuAssertIntEquals (test, 0, info.use_fast_read);
	CuAssertIntEquals (test, 0x6b, info.read_opcode);
	CuAssertIntEquals (test, 1, info.read_dummy);
	CuAssertIntEquals (test, 0, info.read_mode);
	CuAssertIntEquals (test, FLASH_FLAG_QUAD_DATA, info.read_flags);

	status = testing_validate_array (macronix, info.device_id, id_length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_with_mode_bytes (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FLASH_DEVICE_INFO_VERSION, info.version);
	CuAssertIntEquals (test, 2 * 1024 * 1024, info.device_size);
	CuAssertIntEquals (test, FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR, info.capabilities);
	CuAssertIntEquals (test, 0, info.use_fast_read);
	CuAssertIntEquals (test, 0xeb, info.read_opcode);
	CuAssertIntEquals (test, 2, info.read_dummy);
	CuAssertIntEquals (test, 1, info.read_mode);
	CuAssertIntEquals (test, FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_DATA, info.read_flags);

	status = testing_validate_array (macronix, info.device_id, id_length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (NULL, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_save_device_info (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_restore_device (CuTest *test)
{
	struct spi_flash flash;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff120e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;
	uint32_t out;
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &mock.base, &info);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, flash2.base.get_device_size);
	CuAssertPtrNotNull (test, flash2.base.read);
	CuAssertPtrNotNull (test, flash2.base.get_page_size);
	CuAssertPtrNotNull (test, flash2.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, flash2.base.write);
	CuAssertPtrNotNull (test, flash2.base.get_sector_size);
	CuAssertPtrNotNull (test, flash2.base.sector_erase);
	CuAssertPtrNotNull (test, flash2.base.get_block_size);
	CuAssertPtrNotNull (test, flash2.base.block_erase);
	CuAssertPtrNotNull (test, flash2.base.chip_erase);

	CuAssertPtrEquals (test, spi_flash_get_device_size, flash2.base.get_device_size);
	CuAssertPtrEquals (test, spi_flash_read, flash2.base.read);
	CuAssertPtrEquals (test, spi_flash_get_page_size, flash2.base.get_page_size);
	CuAssertPtrEquals (test, spi_flash_minimum_write_per_page, flash2.base.minimum_write_per_page);
	CuAssertPtrEquals (test, spi_flash_write, flash2.base.write);
	CuAssertPtrEquals (test, spi_flash_get_sector_size, flash2.base.get_sector_size);
	CuAssertPtrEquals (test, spi_flash_sector_erase, flash2.base.sector_erase);
	CuAssertPtrEquals (test, spi_flash_get_block_size, flash2.base.get_block_size);
	CuAssertPtrEquals (test, spi_flash_block_erase, flash2.base.block_erase);
	CuAssertPtrEquals (test, spi_flash_chip_erase, flash2.base.chip_erase);

	status = spi_flash_get_device_size (&flash2, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash2, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xc2, vendor);
	CuAssertIntEquals (test, 0x2019, device);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_fast_read (CuTest *test)
{
	struct spi_flash flash;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;
	uint32_t out;
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, true, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &mock.base, &info);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, flash2.base.get_device_size);
	CuAssertPtrNotNull (test, flash2.base.read);
	CuAssertPtrNotNull (test, flash2.base.get_page_size);
	CuAssertPtrNotNull (test, flash2.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, flash2.base.write);
	CuAssertPtrNotNull (test, flash2.base.get_sector_size);
	CuAssertPtrNotNull (test, flash2.base.sector_erase);
	CuAssertPtrNotNull (test, flash2.base.get_block_size);
	CuAssertPtrNotNull (test, flash2.base.block_erase);
	CuAssertPtrNotNull (test, flash2.base.chip_erase);

	CuAssertPtrEquals (test, spi_flash_get_device_size, flash2.base.get_device_size);
	CuAssertPtrEquals (test, spi_flash_read, flash2.base.read);
	CuAssertPtrEquals (test, spi_flash_get_page_size, flash2.base.get_page_size);
	CuAssertPtrEquals (test, spi_flash_minimum_write_per_page, flash2.base.minimum_write_per_page);
	CuAssertPtrEquals (test, spi_flash_write, flash2.base.write);
	CuAssertPtrEquals (test, spi_flash_get_sector_size, flash2.base.get_sector_size);
	CuAssertPtrEquals (test, spi_flash_sector_erase, flash2.base.sector_erase);
	CuAssertPtrEquals (test, spi_flash_get_block_size, flash2.base.get_block_size);
	CuAssertPtrEquals (test, spi_flash_block_erase, flash2.base.block_erase);
	CuAssertPtrEquals (test, spi_flash_chip_erase, flash2.base.chip_erase);

	status = spi_flash_get_device_size (&flash2, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash2, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xc2, vendor);
	CuAssertIntEquals (test, 0x2019, device);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_READ_CMD (0x0b, 0x1234, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_4byte_write_erase (CuTest *test)
{
	struct spi_flash flash;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xfff320e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t mode_expected[] = {0x20};
	uint8_t qspi_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;
	uint32_t out;
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, qspi_expected, sizeof (qspi_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &mock.base, &info);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, flash2.base.get_device_size);
	CuAssertPtrNotNull (test, flash2.base.read);
	CuAssertPtrNotNull (test, flash2.base.get_page_size);
	CuAssertPtrNotNull (test, flash2.base.minimum_write_per_page);
	CuAssertPtrNotNull (test, flash2.base.write);
	CuAssertPtrNotNull (test, flash2.base.get_sector_size);
	CuAssertPtrNotNull (test, flash2.base.sector_erase);
	CuAssertPtrNotNull (test, flash2.base.get_block_size);
	CuAssertPtrNotNull (test, flash2.base.block_erase);
	CuAssertPtrNotNull (test, flash2.base.chip_erase);

	CuAssertPtrEquals (test, spi_flash_get_device_size, flash2.base.get_device_size);
	CuAssertPtrEquals (test, spi_flash_read, flash2.base.read);
	CuAssertPtrEquals (test, spi_flash_get_page_size, flash2.base.get_page_size);
	CuAssertPtrEquals (test, spi_flash_minimum_write_per_page, flash2.base.minimum_write_per_page);
	CuAssertPtrEquals (test, spi_flash_write, flash2.base.write);
	CuAssertPtrEquals (test, spi_flash_get_sector_size, flash2.base.get_sector_size);
	CuAssertPtrEquals (test, spi_flash_sector_erase, flash2.base.sector_erase);
	CuAssertPtrEquals (test, spi_flash_get_block_size, flash2.base.get_block_size);
	CuAssertPtrEquals (test, spi_flash_block_erase, flash2.base.block_erase);
	CuAssertPtrEquals (test, spi_flash_chip_erase, flash2.base.chip_erase);

	status = spi_flash_get_device_size (&flash2, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, (2 * 1024 * 1024), out);

	status = spi_flash_is_4byte_address_mode (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (&flash2, &vendor, &device);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xc2, vendor);
	CuAssertIntEquals (test, 0x2019, device);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_4B_CMD (0x12, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash2, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0x21, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash2, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_4B_CMD (0xdc, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash2, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_init_error (CuTest *test)
{
	struct spi_flash flash;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (NULL, &mock.base, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_restore_device (&flash2, NULL, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_restore_device (&flash2, &mock.base, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_restore_device_fast_read_init_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010100,
		0x09010000,
		0xff000030
	};
	uint32_t params[] = {
		0xffd120e5,
		0x00ffffff,
		0x6b08ff00,
		0xbb043b08,
		0xffffffef,
		0xbb04ffff,
		0xff00ffff,
		0xd810200c,
		0xff00ff00
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t id_length = sizeof (macronix);
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, id_length,
		FLASH_EXP_READ_REG (0x9f, id_length));

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &write_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &mock.base, true, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (NULL, &mock.base, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_configure_drive_strength_winbond (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t initial[] = {0xff};
	uint8_t configured[] = {0xbf};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x11, configured, sizeof (configured)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, configured, sizeof (configured),
		FLASH_EXP_READ_REG (0x15, sizeof (configured)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_winbond_set_correctly (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t initial[] = {0xbf};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_macronix (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_unknown (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t unknown[] = {0x11, 0x20, 0x19};
	const size_t length = sizeof (unknown);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, unknown, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_DEVICE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_id_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_read_config_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_write_config_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t initial[] = {0xff};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_read_back_error (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t initial[] = {0xff};
	uint8_t configured[] = {0xbf};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x11, configured, sizeof (configured)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, sizeof (configured)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_configure_drive_strength_config_mismatch (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t initial[] = {0xff};
	uint8_t configured[] = {0xbf};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x11, configured, sizeof (configured)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, initial, sizeof (initial),
		FLASH_EXP_READ_REG (0x15, sizeof (initial)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_configure_drive_strength (&flash);
	CuAssertIntEquals (test, SPI_FLASH_CONFIG_FAILURE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_sector_size (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_sector_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_sector_size_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.get_sector_size (&flash.base, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FLASH_SECTOR_SIZE, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_sector_size_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_sector_size (NULL, &out);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_get_sector_size (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_block_size (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_block_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_block_size_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.get_block_size (&flash.base, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FLASH_BLOCK_SIZE, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_block_size_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_block_size (NULL, &out);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_get_block_size (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_page_size (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_page_size (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_page_size_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.get_page_size (&flash.base, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, FLASH_PAGE_SIZE, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_page_size_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_block_size (NULL, &out);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_get_block_size (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_minimum_write_per_page (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_minimum_write_per_page (&flash, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_minimum_write_per_page_flash_api (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.minimum_write_per_page (&flash.base, &out);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 1, out);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_minimum_write_per_page_null (CuTest *test)
{
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_minimum_write_per_page (NULL, &out);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_minimum_write_per_page (&flash, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}


CuSuite* get_spi_flash_suite ()
{
	CuSuite *suite = CuSuiteNew ();

	SUITE_ADD_TEST (suite, spi_flash_test_init);
	SUITE_ADD_TEST (suite, spi_flash_test_init_null);
	SUITE_ADD_TEST (suite, spi_flash_test_init_fast_read);
	SUITE_ADD_TEST (suite, spi_flash_test_init_fast_read_null);
	SUITE_ADD_TEST (suite, spi_flash_test_release_null);
	SUITE_ADD_TEST (suite, spi_flash_test_release_no_init);
	SUITE_ADD_TEST (suite, spi_flash_test_set_device_size);
	SUITE_ADD_TEST (suite, spi_flash_test_set_device_size_null);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_size_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_size_null);
	SUITE_ADD_TEST (suite, spi_flash_test_read);
	SUITE_ADD_TEST (suite, spi_flash_test_read_max_address);
	SUITE_ADD_TEST (suite, spi_flash_test_read_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_read_fast_read);
	SUITE_ADD_TEST (suite, spi_flash_test_read_fast_read_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_read_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_read_null);
	SUITE_ADD_TEST (suite, spi_flash_test_read_out_of_range);
	SUITE_ADD_TEST (suite, spi_flash_test_read_too_long);
	SUITE_ADD_TEST (suite, spi_flash_test_read_error_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_read_status_error);
	SUITE_ADD_TEST (suite, spi_flash_test_read_error);
	SUITE_ADD_TEST (suite, spi_flash_test_write);
	SUITE_ADD_TEST (suite, spi_flash_test_write_across_page);
	SUITE_ADD_TEST (suite, spi_flash_test_write_multiple_pages);
	SUITE_ADD_TEST (suite, spi_flash_test_write_multiple_pages_not_aligned);
	SUITE_ADD_TEST (suite, spi_flash_test_write_max_address);
	SUITE_ADD_TEST (suite, spi_flash_test_write_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_write_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_write_null);
	SUITE_ADD_TEST (suite, spi_flash_test_write_out_of_range);
	SUITE_ADD_TEST (suite, spi_flash_test_write_too_long);
	SUITE_ADD_TEST (suite, spi_flash_test_write_error_enable);
	SUITE_ADD_TEST (suite, spi_flash_test_write_error_write);
	SUITE_ADD_TEST (suite, spi_flash_test_write_error_second_page);
	SUITE_ADD_TEST (suite, spi_flash_test_write_error_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_write_status_error);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_offset_address);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_max_address);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_null);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_out_of_range);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_error_enable);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_error_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_status_error);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_error);
	SUITE_ADD_TEST (suite, spi_flash_test_sector_erase_wait_error);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_offset_address);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_max_address);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_null);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_out_of_range);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_error_enable);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_error_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_status_error);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_error);
	SUITE_ADD_TEST (suite, spi_flash_test_block_erase_wait_error);
	SUITE_ADD_TEST (suite, spi_flash_test_chip_erase);
	SUITE_ADD_TEST (suite, spi_flash_test_chip_erase_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_chip_erase_null);
	SUITE_ADD_TEST (suite, spi_flash_test_chip_erase_error_enable);
	SUITE_ADD_TEST (suite, spi_flash_test_chip_erase_error_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_chip_erase_status_error);
	SUITE_ADD_TEST (suite, spi_flash_test_chip_erase_error);
	SUITE_ADD_TEST (suite, spi_flash_test_chip_erase_wait_error);
	SUITE_ADD_TEST (suite, spi_flash_test_write_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_no_write_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_write_in_progress_error);
	SUITE_ADD_TEST (suite, spi_flash_test_write_in_progress_null);
	SUITE_ADD_TEST (suite, spi_flash_test_wait_for_write);
	SUITE_ADD_TEST (suite, spi_flash_test_wait_for_write_null);
	SUITE_ADD_TEST (suite, spi_flash_test_wait_for_write_timeout);
	SUITE_ADD_TEST (suite, spi_flash_test_wait_for_write_immediate_timeout);
	SUITE_ADD_TEST (suite, spi_flash_test_wait_for_write_no_timeout);
	SUITE_ADD_TEST (suite, spi_flash_test_wait_for_write_error);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id_twice);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id_read_ff);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id_read_00);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id_null);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id_only_vendor);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id_only_device);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id_error);
	SUITE_ADD_TEST (suite, spi_flash_test_get_device_id_read_after_error);
	SUITE_ADD_TEST (suite, spi_flash_test_reset_device);
	SUITE_ADD_TEST (suite, spi_flash_test_reset_device_null);
	SUITE_ADD_TEST (suite, spi_flash_test_reset_device_error_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_reset_device_status_error);
	SUITE_ADD_TEST (suite, spi_flash_test_reset_device_error_enable);
	SUITE_ADD_TEST (suite, spi_flash_test_reset_device_error_resetting);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_4byte_address_mode);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_4byte_address_mode_null);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_4byte_address_mode_error);
	SUITE_ADD_TEST (suite, spi_flash_test_disable_4byte_address_mode);
	SUITE_ADD_TEST (suite, spi_flash_test_disable_4byte_address_mode_error);
	SUITE_ADD_TEST (suite, spi_flash_test_is_4byte_address_mode_16M);
	SUITE_ADD_TEST (suite, spi_flash_test_is_4byte_address_mode_32M);
	SUITE_ADD_TEST (suite, spi_flash_test_is_4byte_address_mode_null);
	SUITE_ADD_TEST (suite, spi_flash_test_4byte_address_read);
	SUITE_ADD_TEST (suite, spi_flash_test_4byte_address_write);
	SUITE_ADD_TEST (suite, spi_flash_test_4byte_address_sector_erase);
	SUITE_ADD_TEST (suite, spi_flash_test_4byte_address_block_erase);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_macronix);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_winbond);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_spansion);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_unknown);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_null);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_error_id);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_error_read_status);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_error_write_enable);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_error_write_reg);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_error_wait_write);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_error_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_spansion_error_read_status);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_spansion_error_write_enable);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_spansion_error_write_reg);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_spansion_error_wait_write);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_quad_spi_spansion_error_in_progress);
	SUITE_ADD_TEST (suite, spi_flash_test_is_quad_spi_enabled_macronix);
	SUITE_ADD_TEST (suite, spi_flash_test_is_quad_spi_enabled_winbond);
	SUITE_ADD_TEST (suite, spi_flash_test_is_quad_spi_enabled_spansion);
	SUITE_ADD_TEST (suite, spi_flash_test_is_quad_spi_enabled_unknown);
	SUITE_ADD_TEST (suite, spi_flash_test_is_quad_spi_enabled_null);
	SUITE_ADD_TEST (suite, spi_flash_test_is_quad_spi_enabled_error_id);
	SUITE_ADD_TEST (suite, spi_flash_test_is_quad_spi_enabled_error_read_reg);
	SUITE_ADD_TEST (suite, spi_flash_test_clear_block_protect);
	SUITE_ADD_TEST (suite, spi_flash_test_clear_block_protect_already_clear);
	SUITE_ADD_TEST (suite, spi_flash_test_clear_block_protect_null);
	SUITE_ADD_TEST (suite, spi_flash_test_clear_block_protect_error_read);
	SUITE_ADD_TEST (suite, spi_flash_test_clear_block_protect_error_write);
	SUITE_ADD_TEST (suite, spi_flash_test_deep_power_down_enter);
	SUITE_ADD_TEST (suite, spi_flash_test_deep_power_down_release);
	SUITE_ADD_TEST (suite, spi_flash_test_deep_power_down_null);
	SUITE_ADD_TEST (suite, spi_flash_test_deep_power_down_enter_error);
	SUITE_ADD_TEST (suite, spi_flash_test_deep_power_down_release_error);
	SUITE_ADD_TEST (suite, spi_flash_test_force_4byte_address_mode);
	SUITE_ADD_TEST (suite, spi_flash_test_force_4byte_address_mode_null);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_macronix);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_winbond);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_unknown);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_null);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_error_id);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_error_read_reg_macronix);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_error_read_reg_winbond);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_3byte_only_incompatible_spi);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_3byte_4byte_incompatible_spi);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_4byte_only_incompatible_spi);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_null);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_sfdp_error);
	SUITE_ADD_TEST (suite, spi_flash_test_discover_device_properties_large_device);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_4byte_address_mode_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_4byte_address_mode_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_enable_4byte_address_mode_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_detect_4byte_address_mode_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_force_4byte_address_mode_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_force_4byte_address_mode_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_force_4byte_address_mode_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_fast_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_fast_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_fast_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_write_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_write_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_write_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_sector_erase_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_sector_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_sector_erase_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_block_erase_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_block_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_1_block_erase_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_2_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_2_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_2_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_2_read_with_mode_bytes);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_2_read_3byte_only_nonstandard_opcode);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_2_write_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_2_sector_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_2_block_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_2_2_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_2_2_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_2_2_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_2_2_read_with_mode_bytes);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_2_2_read_3byte_only_nonstandard_opcode);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_2_2_write_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_2_2_sector_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_2_2_block_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_2_2_2_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_2_2_2_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_2_2_2_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_2_2_2_read_with_mode_bytes);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_2_2_2_read_3byte_only_nonstandard_opcode);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_2_2_2_write_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_2_2_2_sector_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_2_2_2_block_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_4_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_4_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_4_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_4_read_with_mode_bytes);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_4_read_3byte_only_nonstandard_opcode);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_4_write_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_4_sector_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_1_4_block_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_4_4_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_4_4_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_4_4_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_4_4_read_without_mode_bytes);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_4_4_read_3byte_only_nonstandard_opcode);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_4_4_write_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_4_4_sector_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_1_4_4_block_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_4_4_4_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_4_4_4_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_4_4_4_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_4_4_4_read_without_mode_bytes);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_4_4_4_read_3byte_only_nonstandard_opcode);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_4_4_4_write_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_4_4_4_sector_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_flash_4_4_4_block_erase_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_spi_1_1_1_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_spi_1_1_1_fast_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_spi_1_1_2_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_spi_1_2_2_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_spi_2_2_2_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_spi_1_1_4_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_spi_1_4_4_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_spi_4_4_4_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_1_1_4_read_3byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_1_4_4_read_3byte_4byte);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_1_2_2_read_4byte_only);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_fast_read);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_wake_device);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_reset_device);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_drive_strength);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_wake_reset_and_drive_strength);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_wip_set);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_init_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_init_fast_read_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_wake_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_id_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_wip_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_reset_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_drive_strength_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_sfdp_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_parameters_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_address_mode_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_qspi_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_clear_protect_error);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_id_ff);
	SUITE_ADD_TEST (suite, spi_flash_test_initialize_device_id_00);
	SUITE_ADD_TEST (suite, spi_flash_test_save_device_info);
	SUITE_ADD_TEST (suite, spi_flash_test_save_device_info_initialized_device);
	SUITE_ADD_TEST (suite, spi_flash_test_save_device_info_with_mode_bytes);
	SUITE_ADD_TEST (suite, spi_flash_test_save_device_info_null);
	SUITE_ADD_TEST (suite, spi_flash_test_restore_device);
	SUITE_ADD_TEST (suite, spi_flash_test_restore_device_fast_read);
	SUITE_ADD_TEST (suite, spi_flash_test_restore_device_4byte_write_erase);
	SUITE_ADD_TEST (suite, spi_flash_test_restore_device_init_error);
	SUITE_ADD_TEST (suite, spi_flash_test_restore_device_fast_read_init_error);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_winbond);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_winbond_set_correctly);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_macronix);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_unknown);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_null);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_id_error);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_read_config_error);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_write_config_error);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_read_back_error);
	SUITE_ADD_TEST (suite, spi_flash_test_configure_drive_strength_config_mismatch);
	SUITE_ADD_TEST (suite, spi_flash_test_get_sector_size);
	SUITE_ADD_TEST (suite, spi_flash_test_get_sector_size_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_get_sector_size_null);
	SUITE_ADD_TEST (suite, spi_flash_test_get_block_size);
	SUITE_ADD_TEST (suite, spi_flash_test_get_block_size_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_get_block_size_null);
	SUITE_ADD_TEST (suite, spi_flash_test_get_page_size);
	SUITE_ADD_TEST (suite, spi_flash_test_get_page_size_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_get_page_size_null);
	SUITE_ADD_TEST (suite, spi_flash_test_minimum_write_per_page);
	SUITE_ADD_TEST (suite, spi_flash_test_minimum_write_per_page_flash_api);
	SUITE_ADD_TEST (suite, spi_flash_test_minimum_write_per_page_null);

	return suite;
}
