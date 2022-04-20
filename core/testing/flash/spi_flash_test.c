// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/spi_flash.h"
#include "flash/spi_flash_static.h"
#include "flash/spi_flash_sfdp.h"
#include "flash/flash_common.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/flash/spi_flash_sfdp_testing.h"


TEST_SUITE_LABEL ("spi_flash");


/**
 * Flash device ID to pass to SFDP for testing.
 */
const uint8_t TEST_ID[FLASH_ID_LEN] = {0x11, 0x22, 0x33};

/**
 * SPI master capabilities supporting the full feature set.
 */
const uint32_t FULL_CAPABILITIES = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 |
	FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 |
	FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;


/**
 * Initialize the SFDP interface for property discovery.
 *
 * @param test The test framework.
 * @param sfdp The SFDP interface to initialize.
 * @param flash The flash mock to set the expectations on.
 * @param header The header data to return.
 */
static void spi_flash_testing_init_sfdp (CuTest *test, struct spi_flash_sfdp *sfdp,
	struct flash_master_mock *flash, const uint32_t *header, const uint8_t *id)
{
	int status;
	int header_length = sizeof (uint32_t) * 4;

	status = flash_master_mock_expect_rx_xfer (flash, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (flash, 0, (uint8_t*) header, header_length,
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, header_length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sfdp_init (sfdp, &flash->base);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&flash->mock);
	CuAssertIntEquals (test, 0, status);
}

/**
 * Initialize a SPI flash instance and execute parameter discovery.
 *
 * @param test The test framework.
 * @param flash The SPI interface to initialize.
 * @param state Variable context for the SPI interface.
 * @param mock The flash mock for the SPI device.
 * @param id ID to provide for the device.
 * @param header SFDP header data to return.
 * @param params SFDP basic parameters table to return.
 * @param params_len Length of the SFDP basic parameters table.
 * @param params_addr Address of the SFDP basic parameters table.
 * @param capabilities Capabilities to report for the SPI master.
 * @param fast_read Flag to indicate fast read initialization should be used.
 */
static void spi_flash_testing_init_with_property_discovery (CuTest *test,
	struct spi_flash *flash, struct spi_flash_state *state, struct flash_master_mock *mock,
	const uint8_t *id, const uint32_t *header, const uint32_t *params, size_t params_len,
	uint32_t params_addr, uint32_t capabilities, bool fast_read)
{
	struct spi_flash_sfdp sfdp;
	int status;

	status = flash_master_mock_init (mock);
	CuAssertIntEquals (test, 0, status);

	if (fast_read) {
		status = spi_flash_init_fast_read (flash, state, &mock->base);
	}
	else {
		status = spi_flash_init (flash, state, &mock->base);
	}
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, mock, header, id);

	status = flash_master_mock_expect_rx_xfer (mock, 0, (uint8_t*) params, params_len,
		FLASH_EXP_READ_CMD (0x5a, params_addr, 1, -1, params_len));
	status |= mock_expect (&mock->mock, mock->base.capabilities, mock, capabilities);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (flash, &sfdp);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock->mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_sfdp_release (&sfdp);
}

/**
 * Initialize a SPI flash instance and execute parameter discovery.
 *
 * @param test The test framework.
 * @param flash The SPI interface to initialize.
 * @param state Variable context for the SPI interface.
 * @param mock The flash mock for the SPI device.
 * @param id ID to provide for the device.
 * @param header SFDP header data to return.
 * @param params SFDP basic parameters table to return.
 * @param params_len Length of the SFDP basic parameters table.
 * @param params_addr Address of the SFDP basic parameters table.
 * @param capabilities Capabilities to report for the SPI master.
 */
void spi_flash_testing_discover_params (CuTest *test, struct spi_flash *flash,
	struct spi_flash_state *state, struct flash_master_mock *mock, const uint8_t *id,
	const uint32_t *header, const uint32_t *params, size_t params_len, uint32_t params_addr,
	uint32_t capabilities)
{
	spi_flash_testing_init_with_property_discovery (test, flash, state, mock, id, header, params,
		params_len, params_addr, capabilities, false);
}

/**
 * Initialize a SPI flash instance using fast read commands and execute parameter discovery.
 *
 * @param test The test framework.
 * @param flash The SPI interface to initialize.
 * @param state Variable context for the SPI interface.
 * @param mock The flash mock for the SPI device.
 * @param id ID to provide for the device.
 * @param header SFDP header data to return.
 * @param params SFDP basic parameters table to return.
 * @param params_len Length of the SFDP basic parameters table.
 * @param params_addr Address of the SFDP basic parameters table.
 * @param capabilities Capabilities to report for the SPI master.
 */
void spi_flash_testing_discover_params_fast_read (CuTest *test, struct spi_flash *flash,
	struct spi_flash_state *state, struct flash_master_mock *mock, const uint8_t *id,
	const uint32_t *header, const uint32_t *params, size_t params_len, uint32_t params_addr,
	uint32_t capabilities)
{
	spi_flash_testing_init_with_property_discovery (test, flash, state, mock, id, header, params,
		params_len, params_addr, capabilities, true);
}

/*******************
 * Test cases
 *******************/

static void spi_flash_test_init (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (NULL, &state, &mock.base);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_init (&flash, NULL, &mock.base);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_init (&flash, &state, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_init_fast_read (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_fast_read (NULL, &state, &mock.base);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_init_fast_read (&flash, NULL, &mock.base);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_init_fast_read (&flash, &state, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_static_init (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

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

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_static_init_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;

	TEST_START;

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

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_static_init_null (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash.state = NULL;
	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash.state = &state;
	flash.spi = NULL;
	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_static_init_fast_read (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state_fast_read (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_static_init_fast_read_null (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state_fast_read (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash.state = NULL;
	status = spi_flash_init_state_fast_read (&flash);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash.state = &state;
	flash.spi = NULL;
	status = spi_flash_init_state_fast_read (&flash);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_release_null (CuTest *test)
{
	TEST_START;

	spi_flash_release (NULL);
}

static void spi_flash_test_set_device_size (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t dev_size = 0x100000;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t dev_size = 0x100000;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_get_device_id (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_get_device_id (NULL, &vendor, &device);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_get_device_id_only_vendor (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint8_t vendor;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {0x11, 0x22, 0x33};
	const size_t length = sizeof (data);
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 3;
	uint8_t vendor;
	uint16_t device;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_discover_device_properties_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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

static void spi_flash_test_discover_device_properties_3byte_4byte_no_4byte_cmd_support (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0x81f860e9
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_NO_4BYTE_CMDS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

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

static void spi_flash_test_discover_device_properties_incompatible_4byte_mode_switch (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa4f860e9
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_INCOMPATIBLE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_discover_device_properties_unknown_quad_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	struct spi_flash_sfdp sfdp;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff788000,
		0xa1f860e9
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	spi_flash_testing_init_sfdp (test, &sfdp, &mock, header, TEST_ID);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_discover_device_properties (&flash, &sfdp);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_ENABLE_UNKNOWN, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_4byte_address_mode (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_enable_4byte_address_mode_disable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_enable_4byte_address_mode_16M (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

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
	struct spi_flash_state state;
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

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, true);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

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
	struct spi_flash_state state;
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

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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

static void spi_flash_test_enable_4byte_address_mode_with_write_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa2f8a0e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xe9));

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

static void spi_flash_test_enable_4byte_address_mode_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_enable_4byte_address_mode (NULL, 1);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_enable_4byte_address_mode_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_enable_4byte_address_mode_disable_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_enable_4byte_address_mode_write_enable_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa2f8a0e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

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

static void spi_flash_test_enable_4byte_address_mode_disable_write_enable_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa2f8a0e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_WRITE_ENABLE);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_force_4byte_address_mode (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_force_4byte_address_mode_16M (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

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

static void spi_flash_test_force_4byte_address_mode_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_force_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

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

static void spi_flash_test_force_4byte_address_mode_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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

static void spi_flash_test_force_4byte_address_mode_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_force_4byte_address_mode (&flash, 0);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_force_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_force_4byte_address_mode_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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

	status = flash_master_mock_expect_rx_xfer (&mock, 0, disable_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));
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

static void spi_flash_test_detect_4byte_address_mode_winbond (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
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

	status = flash_master_mock_expect_rx_xfer (&mock, 0, disable_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));
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

static void spi_flash_test_detect_4byte_address_mode_micron (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t micron[] = {0x20, 0xba, 0x19};
	const size_t length = sizeof (micron);
	uint8_t enable_expected[] = {0x01};
	uint8_t disable_expected[] = {~0x01};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, micron, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, enable_expected, 1,
		FLASH_EXP_READ_REG (0x70, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, disable_expected, 1,
		FLASH_EXP_READ_REG (0x70, 1));
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

static void spi_flash_test_detect_4byte_address_mode_unknown (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t unknown[] = {0x11, 0x20, 0x19};
	const size_t length = sizeof (unknown);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_detect_4byte_address_mode_16M (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
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

static void spi_flash_test_detect_4byte_address_mode_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);
	uint8_t enable_expected[] = {0x20};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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
	struct spi_flash_state state;
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

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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

static void spi_flash_test_detect_4byte_address_mode_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_detect_4byte_address_mode_error_read_reg_micron (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t micron[] = {0x20, 0xba, 0x19};
	const size_t length = sizeof (micron);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, micron, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x70, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_detect_4byte_address_mode (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
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

static void spi_flash_test_reset_device_16M (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
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

static void spi_flash_test_reset_device_command_66_99 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
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

static void spi_flash_test_reset_device_command_f0 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f868e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xf0));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_not_supported (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f840e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, SPI_FLASH_RESET_NOT_SUPPORTED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
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

static void spi_flash_test_reset_device_revert_address_mode_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_revert_address_mode_3byte_to_3byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint8_t reset_3b[] = {~0x02};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, winbond, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xe9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reset_3b, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_revert_address_mode_4byte_to_3byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint8_t reset_3b[] = {~0x02};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, winbond, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reset_3b, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_revert_address_mode_3byte_to_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint8_t reset_4b[] = {0x02};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, winbond, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xe9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_revert_address_mode_4byte_to_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint8_t reset_4b[] = {0x02};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, winbond, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_revert_address_mode_4byte_to_3byte_unknown (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_no_revert_address_mode_3byte_to_3byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1e870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, winbond, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xe9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_no_revert_address_mode_4byte_to_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1e870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, winbond, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_revert_address_mode_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_static (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_STATUS_WIP;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_error_in_progress_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_status_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_revert_check_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, winbond, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_error_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0x66));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_reset_device_error_resetting (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f870e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = spi_flash_reset_device (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = spi_flash_is_4byte_address_mode (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_read (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init_fast_read (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init_fast_read (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_read_switch_4byte_address (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	/* A small device that supports switching address modes is not a normal scenario.  Override the
	 * internal capabilities to allow it to happen.  If the device size was just increased, the
	 * native 4 byte commands would be used. */
	state.capabilities = (FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

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

static void spi_flash_test_read_flash_1_1_1_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_1_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_1_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_fast_read_flash_1_1_1_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params_fast_read (test, &flash, &state, &mock, TEST_ID, header,
		params, sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_fast_read_flash_1_1_1_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params_fast_read (test, &flash, &state, &mock, TEST_ID, header,
		params, sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_fast_read_flash_1_1_1_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params_fast_read (test, &flash, &state, &mock, TEST_ID, header,
		params, sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_2_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_2_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_2_with_mode_bytes (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_2_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_2_2_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_2_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_2_2_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_2_2_with_mode_bytes (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_2_2_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_2_2_2_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_2_2_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_2_2_2_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_2_2_2_with_mode_bytes (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_2_2_2_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_4_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_4_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_4_with_mode_bytes (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_1_4_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_4_4_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_4_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_4_4_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_4_4_without_mode_bytes (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_1_4_4_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_4_4_4_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_4_4_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_4_4_4_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_4_4_4_without_mode_bytes (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flash_4_4_4_3byte_only_nonstandard_opcode (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_spi_1_1_1_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_fast_read_spi_1_1_1_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params_fast_read (test, &flash, &state, &mock, TEST_ID, header,
		params, sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_spi_1_1_2_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_spi_1_2_2_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_spi_2_2_2_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_spi_1_1_4_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_spi_1_4_4_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_spi_4_4_4_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_read_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
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

static void spi_flash_test_read_static (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
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

static void spi_flash_test_read_static_fast_read (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state_fast_read (&flash);
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

static void spi_flash_test_read_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data_in[4];
	size_t length = sizeof (data_in);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data_in[4];
	size_t length = sizeof (data_in);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data_in[4];
	size_t length = sizeof (data_in);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 4;
	uint8_t data_in[length];
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_read_error_in_progress_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 4;
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 4;
	uint8_t data_in[length];

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	const size_t length = 4;
	uint8_t data_in[length];
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_write_switch_4byte_address (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	/* A small device that supports switching address modes is not a normal scenario.  Override the
	 * internal capabilities to allow it to happen.  If the device size was just increased, the
	 * native 4 byte commands would be used. */
	state.capabilities = (FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

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

static void spi_flash_test_write_flash_1_1_1_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flash_1_1_1_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flash_1_1_1_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flash_1_1_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flash_1_2_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flash_2_2_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flash_1_1_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flash_1_4_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flash_4_4_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_write_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_CMD (0x02, 0x1234, 0, cmd_expected, sizeof (cmd_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_write (&flash, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, sizeof (cmd_expected), status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_static (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
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

static void spi_flash_test_write_static_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.write (&flash.base, 0x1234, cmd_expected, sizeof (cmd_expected));
	CuAssertIntEquals (test, SPI_FLASH_READ_ONLY_INTERFACE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_write_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	uint8_t cmd_expected[] = {0x01};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_write_error_in_progress_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_sector_erase_switch_4byte_address (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	/* A small device that supports switching address modes is not a normal scenario.  Override the
	 * internal capabilities to allow it to happen.  If the device size was just increased, the
	 * native 4 byte commands would be used. */
	state.capabilities = (FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

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

static void spi_flash_test_sector_erase_flash_1_1_1_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flash_1_1_1_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flash_1_1_1_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flash_1_1_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flash_1_2_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flash_2_2_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flash_1_1_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flash_1_4_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flash_4_4_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_sector_erase_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0x20, 0x1000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_sector_erase (&flash, 0x1000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_static (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
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

static void spi_flash_test_sector_erase_static_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.sector_erase (&flash.base, 0x1000);
	CuAssertIntEquals (test, SPI_FLASH_READ_ONLY_INTERFACE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_sector_erase_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_sector_erase_error_in_progress_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_block_erase_switch_4byte_address (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	/* A small device that supports switching address modes is not a normal scenario.  Override the
	 * internal capabilities to allow it to happen.  If the device size was just increased, the
	 * native 4 byte commands would be used. */
	state.capabilities = (FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

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

static void spi_flash_test_block_erase_flash_1_1_1_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flash_1_1_1_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flash_1_1_1_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flash_1_1_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flash_1_2_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flash_2_2_2_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flash_1_1_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flash_1_4_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flash_4_4_4_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff288000,
		0xa1f860e9
	};
	uint32_t capabilities = FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_4_4_4 | FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR |
		FLASH_CAP_4BYTE_ADDR;

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, capabilities);

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

static void spi_flash_test_block_erase_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_ERASE_CMD (0xd8, 0x10000));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_block_erase (&flash, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_static (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
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

static void spi_flash_test_block_erase_static_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.block_erase (&flash.base, 0x10000);
	CuAssertIntEquals (test, SPI_FLASH_READ_ONLY_INTERFACE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_block_erase_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_block_erase_error_in_progress_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_chip_erase_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xc7));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_static (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
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

static void spi_flash_test_chip_erase_static_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.chip_erase (&flash.base);
	CuAssertIntEquals (test, SPI_FLASH_READ_ONLY_INTERFACE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_chip_erase (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_chip_erase_error_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_chip_erase_error_in_progress_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_get_sector_size (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_get_sector_size_static_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.get_sector_size (&flash.base, &out);
	CuAssertIntEquals (test, SPI_FLASH_READ_ONLY_INTERFACE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_sector_size_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_get_block_size_static_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.get_block_size (&flash.base, &out);
	CuAssertIntEquals (test, SPI_FLASH_READ_ONLY_INTERFACE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_block_size_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_get_page_size_static_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.get_page_size (&flash.base, &out);
	CuAssertIntEquals (test, SPI_FLASH_READ_ONLY_INTERFACE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_get_page_size_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_minimum_write_per_page_static_read_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_READ_ONLY_API_INIT, &state,
		&mock.base);
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
	CuAssertIntEquals (test, 0, status);

	status = flash.base.minimum_write_per_page (&flash.base, &out);
	CuAssertIntEquals (test, SPI_FLASH_READ_ONLY_INTERFACE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_minimum_write_per_page_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_is_write_in_progress (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_is_write_in_progress_no_write (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_is_write_in_progress_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_write_in_progress (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_write_in_progress_no_write_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_write_in_progress (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_write_in_progress_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_is_write_in_progress_null (CuTest *test)
{
	int status;

	TEST_START;

	status = spi_flash_is_write_in_progress (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);
}

static void spi_flash_test_wait_for_write (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_wait_for_write_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t read_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff088000,
		0x80f820e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_wait_for_write (NULL, 100);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_wait_for_write_timeout (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_STATUS_WIP;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_enable_quad_spi_no_quad_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b27eb29,
		0xbb273b27,
		0xffffffff,
		0xbb27ffff,
		0xeb29ffff,
		0xd810200c,
		0x0000520f,
		0x00994a24,
		0xd4038e8b,
		0x382701ac,
		0x757a757a,
		0x5cd5bdf7,
		0xff020f4a,
		0x363dbd81
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_no_quad_enable_hold_disable_flag_status_register (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_FLAG_STATUS_READY;
	uint8_t reg_enable[] = {0xff, 0xff};
	uint8_t reg_disable[] = {0x00, 0x00};
	uint8_t enable_expected[] = {0xef, 0xff};
	uint8_t disable_expected[] = {0x10, 0x00};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, FLASH_ID_MT25Q256ABA,
		SFDP_HEADER_MT25Q256ABA, SFDP_PARAMS_MT25Q256ABA, SFDP_PARAMS_MT25Q256ABA_LEN,
		SFDP_PARAMS_ADDR_MT25Q256ABA, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0xb5, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0xb1, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0xb5, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0xb1, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_no_quad_enable_hold_disable_volatile_write_enable (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0xff, 0xff};
	uint8_t reg_disable[] = {0x00, 0x00};
	uint8_t enable_expected[] = {0xef, 0xff};
	uint8_t disable_expected[] = {0x10, 0x00};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b27eb29,
		0xbb273b27,
		0xffffffff,
		0xbb27ffff,
		0xeb29ffff,
		0xd810200c,
		0x0000520f,
		0x00994a24,
		0xd4038e8b,
		0x382701ac,
		0x757a757a,
		0x5cd5bdf7,
		0xff820f4a,
		0x363dbde4
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0xb5, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0xb1, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0xb5, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0xb1, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint8_t reg_disable[] = {0xff, 0xff};
	uint8_t enable_expected[] = {0x00, 0x02};
	uint8_t disable_expected[] = {0xff, 0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff1df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_volatile_write_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint8_t reg_disable[] = {0xff, 0xff};
	uint8_t enable_expected[] = {0x00, 0x02};
	uint8_t disable_expected[] = {0xff, 0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff1df719,
		0x80f830e4
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_no_clear (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint8_t reg_disable[] = {0xff, 0xff};
	uint8_t enable_expected[] = {0x00, 0x02};
	uint8_t disable_expected[] = {0xff, 0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_no_clear_volatile_write_enable (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint8_t reg_disable[] = {0xff, 0xff};
	uint8_t enable_expected[] = {0x00, 0x02};
	uint8_t disable_expected[] = {0xff, 0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e4
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_read_35 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint8_t reg_disable[] = {0xff, 0xff};
	uint8_t enable_expected[] = {0x00, 0x02};
	uint8_t disable_expected[] = {0xff, 0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff5df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &reg_enable[1], 1,
		FLASH_EXP_READ_REG (0x35, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &reg_disable[1], 1,
		FLASH_EXP_READ_REG (0x35, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_read_35_volatile_write_enable (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint8_t reg_disable[] = {0xff, 0xff};
	uint8_t enable_expected[] = {0x00, 0x02};
	uint8_t disable_expected[] = {0xff, 0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff5df719,
		0x80f830e4
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &reg_enable[1], 1,
		FLASH_EXP_READ_REG (0x35, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &reg_disable[1], 1,
		FLASH_EXP_READ_REG (0x35, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit6_sr1 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00};
	uint8_t reg_disable[] = {0xff};
	uint8_t enable_expected[] = {0x40};
	uint8_t disable_expected[] = {0xbf};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit6_sr1_volatile_write_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00};
	uint8_t reg_disable[] = {0xff};
	uint8_t enable_expected[] = {0x40};
	uint8_t disable_expected[] = {0xbf};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e4
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit7_sr2 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00};
	uint8_t reg_disable[] = {0xff};
	uint8_t enable_expected[] = {0x80};
	uint8_t disable_expected[] = {0x7f};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff3df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x3f, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x3e, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x3f, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x3e, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_bit7_sr2_volatile_write_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00};
	uint8_t reg_disable[] = {0xff};
	uint8_t enable_expected[] = {0x80};
	uint8_t disable_expected[] = {0x7f};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff3df719,
		0x80f830e4
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x3f, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x3e, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x3f, sizeof (reg_disable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x3e, disable_expected, sizeof (disable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, 0, status);

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

static void spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_read_35_sr2_read_error (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff5df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x35, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_read_reg_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff1df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x05, 2));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 0);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_error_in_progress (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = FLASH_STATUS_WIP;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff1df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

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

static void spi_flash_test_enable_quad_spi_quad_enable_error_in_progress_flag_status_register (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff1df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, SPI_FLASH_WRITE_IN_PROGRESS, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_enable_quad_spi_quad_enable_write_reg_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t read_status = 0;
	uint8_t reg_enable[] = {0x00, 0x00};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff1df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

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

static void spi_flash_test_is_quad_spi_enabled_no_quad_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b27eb29,
		0xbb273b27,
		0xffffffff,
		0xbb27ffff,
		0xeb29ffff,
		0xd810200c,
		0x0000520f,
		0x00994a24,
		0xd4038e8b,
		0x382701ac,
		0x757a757a,
		0x5cd5bdf7,
		0xff020f4a,
		0x363dbd81
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_enable_quad_spi (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_no_quad_enable_hold_disable (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_enable[] = {0xef, 0xff};
	uint8_t reg_disable[] = {0x10, 0x00};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, FLASH_ID_MT25Q256ABA,
		SFDP_HEADER_MT25Q256ABA, SFDP_PARAMS_MT25Q256ABA, SFDP_PARAMS_MT25Q256ABA_LEN,
		SFDP_PARAMS_ADDR_MT25Q256ABA, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0xb5, sizeof (reg_enable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0xb5, sizeof (reg_disable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_quad_enable_bit1_sr2 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_enable[] = {0x00, 0x02};
	uint8_t reg_disable[] = {0xff, 0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff1df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_quad_enable_bit1_sr2_no_clear (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_enable[] = {0x00, 0x02};
	uint8_t reg_disable[] = {0xff, 0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_quad_enable_bit1_sr2_read_35 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_enable[] = {0x02};
	uint8_t reg_disable[] = {0xfd};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff5df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x35, sizeof (reg_enable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x35, sizeof (reg_disable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_quad_enable_bit6_sr1 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_enable[] = {0x40};
	uint8_t reg_disable[] = {0xbf};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_enable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_disable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_quad_spi_enabled_quad_enable_bit7_sr2 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_enable[] = {0x80};
	uint8_t reg_disable[] = {0x7f};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff3df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_enable, sizeof (reg_enable),
		FLASH_EXP_READ_REG (0x3f, sizeof (reg_enable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reg_disable, sizeof (reg_disable),
		FLASH_EXP_READ_REG (0x3f, sizeof (reg_disable)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, 0, status);

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

static void spi_flash_test_is_quad_spi_enabled_read_reg_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff1df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x05, 2));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_quad_spi_enabled (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect_no_quad_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t reg_set[] = {0xff};
	uint8_t clear_expected[] = {0x83};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b27eb29,
		0xbb273b27,
		0xffffffff,
		0xbb27ffff,
		0xeb29ffff,
		0xd810200c,
		0x0000520f,
		0x00994a24,
		0xd4038e8b,
		0x382701ac,
		0x757a757a,
		0x5cd5bdf7,
		0xff020f4a,
		0x363dbd81
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

static void spi_flash_test_clear_block_protect_no_quad_enable_hold_disable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t reg_set[] = {0xff};
	uint8_t clear_expected[] = {0x83};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfffb20e5,
		0x0fffffff,
		0x6b27eb29,
		0xbb273b27,
		0xffffffff,
		0xbb27ffff,
		0xeb29ffff,
		0xd810200c,
		0x0000520f,
		0x00994a24,
		0xd4038e8b,
		0x382701ac,
		0x757a757a,
		0x5cd5bdf7,
		0xff820f4a,
		0x363dbd81
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

static void spi_flash_test_clear_block_protect_quad_enable_bit1_sr2 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t reg_set[] = {0xff, 0xff};
	uint8_t clear_expected[] = {0x83, 0xff};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff1df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

static void spi_flash_test_clear_block_protect_quad_enable_bit1_sr2_no_clear (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t reg_set[] = {0xff};
	uint8_t clear_expected[] = {0x83};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

static void spi_flash_test_clear_block_protect_quad_enable_bit1_sr2_read_35 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t reg_set[] = {0xff, 0xff};
	uint8_t clear_expected[] = {0x83, 0xff};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff5df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &reg_set[1], 1,
		FLASH_EXP_READ_REG (0x35, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

static void spi_flash_test_clear_block_protect_quad_enable_bit6_sr1 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t reg_set[] = {0xff};
	uint8_t clear_expected[] = {0xc3};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

static void spi_flash_test_clear_block_protect_quad_enable_bit7_sr2 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t reg_set[] = {0xff};
	uint8_t clear_expected[] = {0x83};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff3df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

static void spi_flash_test_clear_block_protect_volatile_write_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = 0;
	uint8_t reg_set[] = {0xff};
	uint8_t clear_expected[] = {0x83};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e4
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

static void spi_flash_test_clear_block_protect_flag_status_register (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_FLAG_STATUS_READY;
	uint8_t reg_set[] = {0xff};
	uint8_t clear_expected[] = {0x83};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, clear_expected, sizeof (clear_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_clear[] = {0x83};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_clear, sizeof (reg_clear),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_clear)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_clear_block_protect (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect_already_clear_quad_enable_bit6_sr1 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_clear[] = {0xc3};
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_clear, sizeof (reg_clear),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_clear)));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_clear_block_protect (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect_microchip (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, FLASH_ID_SST26VF064B, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x98));

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

static void spi_flash_test_clear_block_protect_error_id (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_clear_block_protect (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect_error_read (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

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

static void spi_flash_test_clear_block_protect_error_write (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t reg_set[] = {0xff};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reg_set, sizeof (reg_set),
		FLASH_EXP_READ_REG (0x05, sizeof (reg_set)));

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

static void spi_flash_test_clear_block_protect_error_read_35 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff5df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x35, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_clear_block_protect (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_clear_block_protect_error_microchip (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, FLASH_ID_SST26VF064B, 3,
		FLASH_EXP_READ_REG (0x9f, 3));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0x98));

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_deep_power_down_enter_discover_params (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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

static void spi_flash_test_deep_power_down_enter_not_supported (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x800000f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_deep_power_down (&flash, 1);
	CuAssertIntEquals (test, SPI_FLASH_PWRDOWN_NOT_SUPPORTED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_deep_power_down_enter_static (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_deep_power_down_release_discover_params (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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

static void spi_flash_test_deep_power_down_release_not_supported (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x800000f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_deep_power_down (&flash, 0);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_deep_power_down_release_static (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init_state (&flash);
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

static void spi_flash_test_deep_power_down_nonstandard_opcodes (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x7cd7a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xf9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xaf));
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};
	uint32_t params[] = {
		0xfff920e5,
		0x00ffffff,
		0x6b08eb44,
		0xbb423b08,
		0xfffffffe,
		0x0000ffff,
		0xeb40ffff,
		0x520f200c,
		0x0000d810,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

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

static void spi_flash_test_configure_drive_strength_winbond (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t initial[] = {0xbf};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_configure_drive_strength_no_operation (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t unknown[] = {0x11, 0x20, 0x19};
	const size_t length = sizeof (unknown);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, unknown, length,
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

static void spi_flash_test_configure_drive_strength_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t initial[] = {0xff};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
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

	status = spi_flash_init (&flash, &state, &mock.base);
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

static void spi_flash_test_initialize_device_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x20};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t mode_expected[] = {0x20};
	uint8_t qspi_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, true, false, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Release deep power down. */
	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, true, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Reset the device. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, true, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint8_t initial = 0x00;
	uint8_t configured = 0x20;
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x00;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, true, false, false, true);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint8_t initial = 0x00;
	uint8_t configured = 0x20;
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x00;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Release deep power down. */
	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, true, true, true);
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
	struct spi_flash_state state;
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
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (NULL, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_initialize_device (&flash, NULL, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_initialize_device (&flash, &state, NULL, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_init_fast_read_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (NULL, &state, &mock.base, true, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_initialize_device (&flash, NULL, &mock.base, true, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_initialize_device (&flash, &state, NULL, true, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_wake_error (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, true, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_id_error (CuTest *test)
{
	struct spi_flash_state state;
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_sfdp_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, 16));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_parameters_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, 0x40));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_wip_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_reset_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Reset the device. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, true, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_drive_strength_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f970e9
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Configure output drive strength. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, true, false, false, true);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_address_mode_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_qspi_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_clear_protect_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_id_ff (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t id[] = {0xff, 0xff, 0xff};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_NO_DEVICE, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_id_00 (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t id[] = {0x00, 0x00, 0x00};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_NO_DEVICE, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_3byte_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
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

static void spi_flash_test_initialize_device_state_3byte_4byte (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x20};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
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

static void spi_flash_test_initialize_device_state_4byte_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
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

static void spi_flash_test_initialize_device_state_1_1_4_read_3byte_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
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

static void spi_flash_test_initialize_device_state_1_4_4_read_3byte_4byte (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t mode_expected[] = {0x20};
	uint8_t qspi_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
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

static void spi_flash_test_initialize_device_state_1_2_2_read_4byte_only (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
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

static void spi_flash_test_initialize_device_state_fast_read (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device_state (&flash, true, false, false, false);
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

static void spi_flash_test_initialize_device_state_wake_device (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Release deep power down. */
	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device_state (&flash, false, true, false, false);
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

static void spi_flash_test_initialize_device_state_reset_device (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Reset the device. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

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

	status = spi_flash_initialize_device_state (&flash, false, false, true, false);
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

static void spi_flash_test_initialize_device_state_drive_strength (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint8_t initial = 0x00;
	uint8_t configured = 0x20;
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x00;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

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

	status = spi_flash_initialize_device_state (&flash, true, false, false, true);
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

static void spi_flash_test_initialize_device_state_wake_reset_and_drive_strength (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0x80f830e9
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	uint8_t initial = 0x00;
	uint8_t configured = 0x20;
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x00;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Release deep power down. */
	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));

	/* Get Device ID. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

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

	status = spi_flash_initialize_device_state (&flash, false, true, true, true);
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

static void spi_flash_test_initialize_device_state_wip_set (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint8_t wip_set = FLASH_STATUS_WIP;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	uint32_t out;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_set, 1,
			FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
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

static void spi_flash_test_initialize_device_state_init_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (NULL, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash.state = NULL;
	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash.state = &state;
	flash.spi = NULL;
	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_init_fast_read_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (NULL, true, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash.state = NULL;
	status = spi_flash_initialize_device_state (&flash, true, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash.state = &state;
	flash.spi = NULL;
	status = spi_flash_initialize_device_state (&flash, true, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_wake_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Release deep power down. */
	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_OPCODE (0xab));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, true, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_id_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_sfdp_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, 16));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_parameters_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
		0xff000030
	};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, TEST_ID, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, 0x40));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_wip_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_reset_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Reset the device. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, true, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_drive_strength_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xd314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff4df719,
		0xa5f970e9
	};
	uint8_t winbond[] = {0xef, 0x40, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, winbond, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Configure output drive strength. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, true, false, false, true);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_initialize_device_state_address_mode_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_qspi_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_clear_protect_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_id_ff (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t id[] = {0xff, 0xff, 0xff};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_NO_DEVICE, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_initialize_device_state_id_00 (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint8_t id[] = {0x00, 0x00, 0x00};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, id, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, SPI_FLASH_NO_DEVICE, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_save_device_info (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	CuAssertIntEquals (test, 0x99, info.reset_opcode);
	CuAssertIntEquals (test, 0xb9, info.enter_pwrdown);
	CuAssertIntEquals (test, 0xab, info.release_pwrdown);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED, info.switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_NO_QE_BIT, info.quad_enable);
	CuAssertIntEquals (test, SPI_FLASH_DEVICE_INFO_RESET_3BYTE, info.flags);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_initialized_device (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	CuAssertIntEquals (test, 0x99, info.reset_opcode);
	CuAssertIntEquals (test, 0xb9, info.enter_pwrdown);
	CuAssertIntEquals (test, 0xab, info.release_pwrdown);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED, info.switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1, info.quad_enable);
	CuAssertIntEquals (test, 0, info.flags);

	status = testing_validate_array (macronix, info.device_id, FLASH_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_with_mode_bytes (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	CuAssertIntEquals (test, 0x99, info.reset_opcode);
	CuAssertIntEquals (test, 0xb9, info.enter_pwrdown);
	CuAssertIntEquals (test, 0xab, info.release_pwrdown);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED, info.switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1, info.quad_enable);
	CuAssertIntEquals (test, 0, info.flags);

	status = testing_validate_array (macronix, info.device_id, FLASH_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_initialized_device_3byte_4byte_write_enable (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x82f8b0e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t mode_expected[] = {0x20};
	uint8_t qspi_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	CuAssertIntEquals (test, SPI_FLASH_DEVICE_INFO_VERSION, info.version);
	CuAssertIntEquals (test, 2 * 1024 * 1024, info.device_size);
	CuAssertIntEquals (test, FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 |
		FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR, info.capabilities);
	CuAssertIntEquals (test, 0, info.use_fast_read);
	CuAssertIntEquals (test, 0x6c, info.read_opcode);
	CuAssertIntEquals (test, 1, info.read_dummy);
	CuAssertIntEquals (test, 0, info.read_mode);
	CuAssertIntEquals (test, FLASH_FLAG_QUAD_DATA | FLASH_FLAG_4BYTE_ADDRESS, info.read_flags);
	CuAssertIntEquals (test, 0x99, info.reset_opcode);
	CuAssertIntEquals (test, 0xb9, info.enter_pwrdown);
	CuAssertIntEquals (test, 0xab, info.release_pwrdown);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_COMMAND_WRITE_ENABLE, info.switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1, info.quad_enable);
	CuAssertIntEquals (test, SPI_FLASH_DEVICE_INFO_RESET_3BYTE, info.flags);

	status = testing_validate_array (macronix, info.device_id, FLASH_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_flag_status_register_volatile_write_enable (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t wip_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff2df719,
		0x80f830e4
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	CuAssertIntEquals (test, 0x99, info.reset_opcode);
	CuAssertIntEquals (test, 0xb9, info.enter_pwrdown);
	CuAssertIntEquals (test, 0xab, info.release_pwrdown);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED, info.switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1, info.quad_enable);
	CuAssertIntEquals (test, SPI_FLASH_DEVICE_INFO_BUSY_FLAG | SPI_FLASH_DEVICE_INFO_SR1_VOLATILE,
		info.flags);

	status = testing_validate_array (macronix, info.device_id, FLASH_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_nonstandard_deep_powerdown (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x7cd7a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
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
	CuAssertIntEquals (test, 0x99, info.reset_opcode);
	CuAssertIntEquals (test, 0xf9, info.enter_pwrdown);
	CuAssertIntEquals (test, 0xaf, info.release_pwrdown);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_4BYTE_MODE_UNSUPPORTED, info.switch_4byte);
	CuAssertIntEquals (test, SPI_FLASH_SFDP_QUAD_QE_BIT6_SR1, info.quad_enable);
	CuAssertIntEquals (test, 0, info.flags);

	status = testing_validate_array (macronix, info.device_id, FLASH_ID_LEN);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);
}

static void spi_flash_test_save_device_info_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct spi_flash_state state2;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &state2, &mock.base, &info);
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
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_fast_read (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct spi_flash_state state2;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, true, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &state2, &mock.base, &info);
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
	struct spi_flash_state state;
	struct spi_flash flash;
	struct spi_flash_state state2;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &state2, &mock.base, &info);
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

static void spi_flash_test_restore_device_3byte_4byte_write_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct spi_flash_state state2;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x82f8b0e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &state2, &mock.base, &info);
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
		FLASH_EXP_1_1_4_READ_4B_CMD (0x6c, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash2);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_flag_status_register_volatile_write_enable (
	CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct spi_flash_state state2;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff2df719,
		0x80f830e4
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &state2, &mock.base, &info);
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

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash2, 1);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_nonstandard_deep_powerdown (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct spi_flash_state state2;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x7cd7a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (&flash2, &state2, &mock.base, &info);
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
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xf9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xaf));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct spi_flash_state state2;
	struct spi_flash flash2;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (NULL, &state2, &mock.base, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_restore_device (&flash2, NULL, &mock.base, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_restore_device (&flash2, &state2, NULL, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_restore_device (&flash2, &state2, &mock.base, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_restore_device_fast_read_init_error (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct spi_flash_state state2;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
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

	status = spi_flash_initialize_device (&flash, &state, &mock.base, true, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device (NULL, &state2, &mock.base, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_restore_device_state (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	struct spi_flash_state state2;
	struct spi_flash flash2 = spi_flash_static_init (SPI_FLASH_API_INIT, &state2, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device_state (&flash2, &info);
	CuAssertIntEquals (test, 0, status);

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
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_state_fast_read (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	struct spi_flash_state state2;
	struct spi_flash flash2 = spi_flash_static_init (SPI_FLASH_API_INIT, &state2, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
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

	status = spi_flash_initialize_device_state (&flash, true, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device_state (&flash2, &info);
	CuAssertIntEquals (test, 0, status);

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

static void spi_flash_test_restore_device_state_4byte_write_erase (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	struct spi_flash_state state2;
	struct spi_flash flash2 = spi_flash_static_init (SPI_FLASH_API_INIT, &state2, &mock.base);
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device_state (&flash2, &info);
	CuAssertIntEquals (test, 0, status);

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

static void spi_flash_test_restore_device_state_3byte_4byte_write_enable (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	struct spi_flash_state state2;
	struct spi_flash flash2 = spi_flash_static_init (SPI_FLASH_API_INIT, &state2, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x82f8b0e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Detect address mode. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, mode_expected, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device_state (&flash2, &info);
	CuAssertIntEquals (test, 0, status);

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
		FLASH_EXP_1_1_4_READ_4B_CMD (0x6c, 0x1234, 1, 0, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb7));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash2);
	CuAssertIntEquals (test, 1, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_state_flag_status_register_volatile_write_enable (
	CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	struct spi_flash_state state2;
	struct spi_flash flash2 = spi_flash_static_init (SPI_FLASH_API_INIT, &state2, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = FLASH_FLAG_STATUS_READY;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2fb,
		0xff2df719,
		0x80f830e4
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	/* Clear block protect bits. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, &write_status, 1));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device_state (&flash2, &info);
	CuAssertIntEquals (test, 0, status);

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

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x50));
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_4byte_address_mode (&flash2, 1);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_ADDR_MODE, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_FLAG_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xb9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xab));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_state_nonstandard_deep_powerdown (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	struct spi_flash_state state2;
	struct spi_flash flash2 = spi_flash_static_init (SPI_FLASH_API_INIT, &state2, &mock.base);
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x7cd7a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
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
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device_state (&flash2, &info);
	CuAssertIntEquals (test, 0, status);

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
		FLASH_EXP_READ_REG (0x05, 1));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_REG (0x01, enable_expected, sizeof (enable_expected)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_enable_quad_spi (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xeb, 0x1234, 2, 1, data_in, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_read (&flash2, 0x1234, data_in, length);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x66));
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0x99));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_reset_device (&flash2);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xf9));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 1);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_OPCODE (0xaf));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_deep_power_down (&flash2, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash2);
}

static void spi_flash_test_restore_device_state_null (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	struct spi_flash_state state2;
	struct spi_flash flash2 = spi_flash_static_init (SPI_FLASH_API_INIT, &state2, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t enable_expected[] = {0x40};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_DUAL_2_2_2 | FLASH_CAP_DUAL_1_2_2 | FLASH_CAP_DUAL_1_1_2 | FLASH_CAP_QUAD_4_4_4 |
		FLASH_CAP_QUAD_1_4_4 | FLASH_CAP_QUAD_1_1_4 | FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);

	/* Enable QSPI. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_REG (0x05, 1));

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

	status = spi_flash_initialize_device_state (&flash, false, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device_state (NULL, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_restore_device_state (&flash2, NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash2.state = NULL;
	status = spi_flash_restore_device_state (&flash2, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	flash2.state = &state;
	flash2.spi = NULL;
	status = spi_flash_restore_device_state (&flash2, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_restore_device_state_fast_read_init_error (CuTest *test)
{
	struct flash_master_mock mock;
	struct spi_flash_state state;
	struct spi_flash flash = spi_flash_static_init (SPI_FLASH_API_INIT, &state, &mock.base);
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff2df719,
		0x80f830e9
	};
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	uint8_t read_status = 0x7c;
	uint8_t write_status = 0x40;
	struct spi_flash_device_info info;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	/* Get Device ID. */
	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));

	/* Use SFDP to discover device properties. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, macronix, FLASH_ID_LEN,
		FLASH_EXP_READ_REG (0x9f, FLASH_ID_LEN));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) header, sizeof (header),
		FLASH_EXP_READ_CMD (0x5a, 0x000000, 1, -1, sizeof (header)));
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, (uint8_t*) params, sizeof (params),
		FLASH_EXP_READ_CMD (0x5a, 0x000030, 1, -1, sizeof (params)));
	status |= mock_expect (&mock.mock, mock.base.capabilities, &mock,
		FLASH_CAP_3BYTE_ADDR | FLASH_CAP_4BYTE_ADDR);

	/* Detect device WIP state. */
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, &WIP_STATUS, 1,
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

	status = spi_flash_initialize_device_state (&flash, true, false, false, false);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_save_device_info (&flash, &info);
	CuAssertIntEquals (test, 0, status);

	spi_flash_release (&flash);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_restore_device_state (NULL, &info);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&mock);
	CuAssertIntEquals (test, 0, status);
}

static void spi_flash_test_is_address_mode_fixed (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_address_mode_fixed (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_address_mode_fixed_16M (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_address_mode_fixed (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_address_mode_fixed_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_is_address_mode_fixed (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_address_mode_fixed_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_is_address_mode_fixed (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_address_mode_fixed_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_is_address_mode_fixed (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_address_mode_fixed_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_address_mode_fixed (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_address_mode_requires_write_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_address_mode_requires_write_enable (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_address_mode_requires_write_enable_16M (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_address_mode_requires_write_enable (&flash);
	CuAssertIntEquals (test, SPI_FLASH_ADDR_MODE_FIXED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_address_mode_requires_write_enable_with_write_enable (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa2f8a0e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_address_mode_requires_write_enable (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_address_mode_requires_write_enable_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_address_mode_requires_write_enable (&flash);
	CuAssertIntEquals (test, SPI_FLASH_ADDR_MODE_FIXED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_address_mode_requires_write_enable_3byte_4byte (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint32_t header[] = {
		0x50444653,
		0xff010106,
		0x10010600,
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
		0xff00ff00,
		0x00a60236,
		0xb314ea82,
		0x337663e9,
		0x757a757a,
		0x5cd5a2f7,
		0xff088000,
		0xa1f860e9
	};

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_address_mode_requires_write_enable (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_address_mode_requires_write_enable_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_address_mode_requires_write_enable (&flash);
	CuAssertIntEquals (test, SPI_FLASH_ADDR_MODE_FIXED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_address_mode_requires_write_enable_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_address_mode_requires_write_enable (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_macronix (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t macronix[] = {0xc2, 0x20, 0x19};
	const size_t length = sizeof (macronix);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, macronix, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_winbond (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);
	uint8_t reset_4b[] = {0x02};
	uint8_t reset_3b[] = {~0x02};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reset_3b, 1,
		FLASH_EXP_READ_REG (0x15, 1));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_micron (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t micron[] = {0x20, 0xba, 0x19};
	const size_t length = sizeof (micron);
	uint8_t reset_4b[] = {~0x01};
	uint8_t reset_3b[] = {0x01};

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, micron, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_rx_xfer (&mock, 0, reset_4b, 1,
		FLASH_EXP_READ_REG (0xb5, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, reset_3b, 1,
		FLASH_EXP_READ_REG (0xb5, 1));
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_unknown (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t unknown[] = {0x11, 0x20, 0x19};
	const size_t length = sizeof (unknown);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, unknown, length,
		FLASH_EXP_READ_REG (0x9f, length));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, SPI_FLASH_UNSUPPORTED_DEVICE, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_16M (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_3byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	TEST_START;

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_4byte_only (CuTest *test)
{
	struct spi_flash_state state;
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

	spi_flash_testing_discover_params (test, &flash, &state, &mock, TEST_ID, header, params,
		sizeof (params), 0x000030, FULL_CAPABILITIES);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, 1, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (NULL);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_error_id (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x9f, 3));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_error_read_reg_winbond (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t winbond[] = {0xef, 0x40, 0x19};
	const size_t length = sizeof (winbond);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, winbond, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0x15, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_is_4byte_address_mode_on_reset_error_read_reg_micron (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t micron[] = {0x20, 0xba, 0x19};
	const size_t length = sizeof (micron);

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, micron, length,
		FLASH_EXP_READ_REG (0x9f, length));

	status |= flash_master_mock_expect_xfer (&mock, FLASH_MASTER_XFER_FAILED,
		FLASH_EXP_READ_REG (0xb5, 1));

	CuAssertIntEquals (test, 0, status);

	status = spi_flash_is_4byte_address_mode_on_reset (&flash);
	CuAssertIntEquals (test, FLASH_MASTER_XFER_FAILED, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_set_read_command (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t data[] = {1, 2, 3, 4};
	const size_t length = sizeof (data);
	uint8_t data_in[length];
	uint8_t wip_status = 0;
	struct spi_flash_sfdp_read_cmd command = {
		.opcode = 0xec,
		.dummy_bytes = 2,
		.mode_bytes = 1
	};
	uint16_t flags = FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_DATA;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_read_command (&flash, &command, flags);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &wip_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (&mock, 0, data, length,
		FLASH_EXP_1_4_4_READ_CMD (0xec, 0x1234, 2, 1, data_in, length));

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

static void spi_flash_test_set_read_command_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	struct spi_flash_sfdp_read_cmd command = {
		.opcode = 0xec,
		.dummy_bytes = 2,
		.mode_bytes = 1
	};
	uint16_t flags = FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_DATA;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_read_command (NULL, &command, flags);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = spi_flash_set_read_command (&flash, NULL, flags);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}

static void spi_flash_test_set_write_command (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;
	uint8_t cmd_expected[] = {0x01, 0x02, 0x03, 0x04};
	uint8_t read_status = 0;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_write_command (&flash, 0x38,
		FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_DATA);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (&mock, 0, &read_status, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_xfer (&mock, 0, FLASH_EXP_WRITE_ENABLE);
	status |= flash_master_mock_expect_tx_xfer (&mock, 0,
		FLASH_EXP_WRITE_EXT_CMD (0x38, 0x1234, 0, 0, cmd_expected, sizeof (cmd_expected),
			FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_DATA));
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

static void spi_flash_test_set_write_command_null (CuTest *test)
{
	struct spi_flash_state state;
	struct spi_flash flash;
	struct flash_master_mock mock;
	int status;

	TEST_START;

	status = flash_master_mock_init (&mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (&flash, &state, &mock.base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (&flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_write_command (NULL, 0x38,
		FLASH_FLAG_QUAD_ADDR | FLASH_FLAG_QUAD_DATA);
	CuAssertIntEquals (test, SPI_FLASH_INVALID_ARGUMENT, status);

	status = mock_validate (&mock.mock);
	CuAssertIntEquals (test, 0, status);

	spi_flash_is_write_in_progress (&flash);

	flash_master_mock_release (&mock);
	spi_flash_release (&flash);
}


TEST_SUITE_START (spi_flash);

TEST (spi_flash_test_init);
TEST (spi_flash_test_init_null);
TEST (spi_flash_test_init_fast_read);
TEST (spi_flash_test_init_fast_read_null);
TEST (spi_flash_test_static_init);
TEST (spi_flash_test_static_init_read_only);
TEST (spi_flash_test_static_init_null);
TEST (spi_flash_test_static_init_fast_read);
TEST (spi_flash_test_static_init_fast_read_null);
TEST (spi_flash_test_release_null);
TEST (spi_flash_test_set_device_size);
TEST (spi_flash_test_set_device_size_null);
TEST (spi_flash_test_get_device_size_flash_api);
TEST (spi_flash_test_get_device_size_null);
TEST (spi_flash_test_get_device_id);
TEST (spi_flash_test_get_device_id_twice);
TEST (spi_flash_test_get_device_id_read_ff);
TEST (spi_flash_test_get_device_id_read_00);
TEST (spi_flash_test_get_device_id_null);
TEST (spi_flash_test_get_device_id_only_vendor);
TEST (spi_flash_test_get_device_id_only_device);
TEST (spi_flash_test_get_device_id_error);
TEST (spi_flash_test_get_device_id_read_after_error);
TEST (spi_flash_test_discover_device_properties_3byte_only);
TEST (spi_flash_test_discover_device_properties_3byte_only_incompatible_spi);
TEST (spi_flash_test_discover_device_properties_3byte_4byte);
TEST (spi_flash_test_discover_device_properties_3byte_4byte_incompatible_spi);
TEST (spi_flash_test_discover_device_properties_3byte_4byte_no_4byte_cmd_support);
TEST (spi_flash_test_discover_device_properties_4byte_only);
TEST (spi_flash_test_discover_device_properties_4byte_only_incompatible_spi);
TEST (spi_flash_test_discover_device_properties_null);
TEST (spi_flash_test_discover_device_properties_sfdp_error);
TEST (spi_flash_test_discover_device_properties_large_device);
TEST (spi_flash_test_discover_device_properties_incompatible_4byte_mode_switch);
TEST (spi_flash_test_discover_device_properties_unknown_quad_enable);
TEST (spi_flash_test_enable_4byte_address_mode);
TEST (spi_flash_test_enable_4byte_address_mode_disable);
TEST (spi_flash_test_enable_4byte_address_mode_16M);
TEST (spi_flash_test_enable_4byte_address_mode_3byte_only);
TEST (spi_flash_test_enable_4byte_address_mode_3byte_4byte);
TEST (spi_flash_test_enable_4byte_address_mode_4byte_only);
TEST (spi_flash_test_enable_4byte_address_mode_with_write_enable);
TEST (spi_flash_test_enable_4byte_address_mode_null);
TEST (spi_flash_test_enable_4byte_address_mode_error);
TEST (spi_flash_test_enable_4byte_address_mode_disable_error);
TEST (spi_flash_test_enable_4byte_address_mode_write_enable_error);
TEST (spi_flash_test_enable_4byte_address_mode_disable_write_enable_error);
TEST (spi_flash_test_is_4byte_address_mode_16M);
TEST (spi_flash_test_is_4byte_address_mode_32M);
TEST (spi_flash_test_is_4byte_address_mode_null);
TEST (spi_flash_test_force_4byte_address_mode);
TEST (spi_flash_test_force_4byte_address_mode_16M);
TEST (spi_flash_test_force_4byte_address_mode_3byte_only);
TEST (spi_flash_test_force_4byte_address_mode_3byte_4byte);
TEST (spi_flash_test_force_4byte_address_mode_4byte_only);
TEST (spi_flash_test_force_4byte_address_mode_null);
TEST (spi_flash_test_detect_4byte_address_mode_macronix);
TEST (spi_flash_test_detect_4byte_address_mode_winbond);
TEST (spi_flash_test_detect_4byte_address_mode_micron);
TEST (spi_flash_test_detect_4byte_address_mode_unknown);
TEST (spi_flash_test_detect_4byte_address_mode_16M);
TEST (spi_flash_test_detect_4byte_address_mode_3byte_only);
TEST (spi_flash_test_detect_4byte_address_mode_3byte_4byte);
TEST (spi_flash_test_detect_4byte_address_mode_4byte_only);
TEST (spi_flash_test_detect_4byte_address_mode_null);
TEST (spi_flash_test_detect_4byte_address_mode_error_id);
TEST (spi_flash_test_detect_4byte_address_mode_error_read_reg_macronix);
TEST (spi_flash_test_detect_4byte_address_mode_error_read_reg_winbond);
TEST (spi_flash_test_detect_4byte_address_mode_error_read_reg_micron);
TEST (spi_flash_test_reset_device);
TEST (spi_flash_test_reset_device_16M);
TEST (spi_flash_test_reset_device_command_66_99);
TEST (spi_flash_test_reset_device_command_f0);
TEST (spi_flash_test_reset_device_not_supported);
TEST (spi_flash_test_reset_device_flag_status_register);
TEST (spi_flash_test_reset_device_revert_address_mode_3byte_only);
TEST (spi_flash_test_reset_device_revert_address_mode_3byte_to_3byte);
TEST (spi_flash_test_reset_device_revert_address_mode_4byte_to_3byte);
TEST (spi_flash_test_reset_device_revert_address_mode_3byte_to_4byte);
TEST (spi_flash_test_reset_device_revert_address_mode_4byte_to_4byte);
TEST (spi_flash_test_reset_device_revert_address_mode_4byte_to_3byte_unknown);
TEST (spi_flash_test_reset_device_no_revert_address_mode_3byte_to_3byte);
TEST (spi_flash_test_reset_device_no_revert_address_mode_4byte_to_4byte);
TEST (spi_flash_test_reset_device_revert_address_mode_4byte_only);
TEST (spi_flash_test_reset_device_static);
TEST (spi_flash_test_reset_device_null);
TEST (spi_flash_test_reset_device_error_in_progress);
TEST (spi_flash_test_reset_device_error_in_progress_flag_status_register);
TEST (spi_flash_test_reset_device_status_error);
TEST (spi_flash_test_reset_device_revert_check_error);
TEST (spi_flash_test_reset_device_error_enable);
TEST (spi_flash_test_reset_device_error_resetting);
TEST (spi_flash_test_read);
TEST (spi_flash_test_read_max_address);
TEST (spi_flash_test_read_4byte);
TEST (spi_flash_test_read_fast_read);
TEST (spi_flash_test_read_fast_read_4byte);
TEST (spi_flash_test_read_flash_api);
TEST (spi_flash_test_read_switch_4byte_address);
TEST (spi_flash_test_read_flash_1_1_1_3byte_only);
TEST (spi_flash_test_read_flash_1_1_1_3byte_4byte);
TEST (spi_flash_test_read_flash_1_1_1_4byte_only);
TEST (spi_flash_test_read_fast_read_flash_1_1_1_3byte_only);
TEST (spi_flash_test_read_fast_read_flash_1_1_1_3byte_4byte);
TEST (spi_flash_test_read_fast_read_flash_1_1_1_4byte_only);
TEST (spi_flash_test_read_flash_1_1_2_3byte_only);
TEST (spi_flash_test_read_flash_1_1_2_3byte_4byte);
TEST (spi_flash_test_read_flash_1_1_2_4byte_only);
TEST (spi_flash_test_read_flash_1_1_2_with_mode_bytes);
TEST (spi_flash_test_read_flash_1_1_2_3byte_only_nonstandard_opcode);
TEST (spi_flash_test_read_flash_1_2_2_3byte_only);
TEST (spi_flash_test_read_flash_1_2_2_3byte_4byte);
TEST (spi_flash_test_read_flash_1_2_2_4byte_only);
TEST (spi_flash_test_read_flash_1_2_2_with_mode_bytes);
TEST (spi_flash_test_read_flash_1_2_2_3byte_only_nonstandard_opcode);
TEST (spi_flash_test_read_flash_2_2_2_3byte_only);
TEST (spi_flash_test_read_flash_2_2_2_3byte_4byte);
TEST (spi_flash_test_read_flash_2_2_2_4byte_only);
TEST (spi_flash_test_read_flash_2_2_2_with_mode_bytes);
TEST (spi_flash_test_read_flash_2_2_2_3byte_only_nonstandard_opcode);
TEST (spi_flash_test_read_flash_1_1_4_3byte_only);
TEST (spi_flash_test_read_flash_1_1_4_3byte_4byte);
TEST (spi_flash_test_read_flash_1_1_4_4byte_only);
TEST (spi_flash_test_read_flash_1_1_4_with_mode_bytes);
TEST (spi_flash_test_read_flash_1_1_4_3byte_only_nonstandard_opcode);
TEST (spi_flash_test_read_flash_1_4_4_3byte_only);
TEST (spi_flash_test_read_flash_1_4_4_3byte_4byte);
TEST (spi_flash_test_read_flash_1_4_4_4byte_only);
TEST (spi_flash_test_read_flash_1_4_4_without_mode_bytes);
TEST (spi_flash_test_read_flash_1_4_4_3byte_only_nonstandard_opcode);
TEST (spi_flash_test_read_flash_4_4_4_3byte_only);
TEST (spi_flash_test_read_flash_4_4_4_3byte_4byte);
TEST (spi_flash_test_read_flash_4_4_4_4byte_only);
TEST (spi_flash_test_read_flash_4_4_4_without_mode_bytes);
TEST (spi_flash_test_read_flash_4_4_4_3byte_only_nonstandard_opcode);
TEST (spi_flash_test_read_spi_1_1_1_3byte_only);
TEST (spi_flash_test_read_fast_read_spi_1_1_1_3byte_only);
TEST (spi_flash_test_read_spi_1_1_2_3byte_only);
TEST (spi_flash_test_read_spi_1_2_2_3byte_only);
TEST (spi_flash_test_read_spi_2_2_2_3byte_only);
TEST (spi_flash_test_read_spi_1_1_4_3byte_only);
TEST (spi_flash_test_read_spi_1_4_4_3byte_only);
TEST (spi_flash_test_read_spi_4_4_4_3byte_only);
TEST (spi_flash_test_read_flag_status_register);
TEST (spi_flash_test_read_static);
TEST (spi_flash_test_read_static_fast_read);
TEST (spi_flash_test_read_null);
TEST (spi_flash_test_read_out_of_range);
TEST (spi_flash_test_read_too_long);
TEST (spi_flash_test_read_error_in_progress);
TEST (spi_flash_test_read_error_in_progress_flag_status_register);
TEST (spi_flash_test_read_status_error);
TEST (spi_flash_test_read_error);
TEST (spi_flash_test_write);
TEST (spi_flash_test_write_across_page);
TEST (spi_flash_test_write_multiple_pages);
TEST (spi_flash_test_write_multiple_pages_not_aligned);
TEST (spi_flash_test_write_max_address);
TEST (spi_flash_test_write_4byte);
TEST (spi_flash_test_write_flash_api);
TEST (spi_flash_test_write_switch_4byte_address);
TEST (spi_flash_test_write_flash_1_1_1_3byte_only);
TEST (spi_flash_test_write_flash_1_1_1_3byte_4byte);
TEST (spi_flash_test_write_flash_1_1_1_4byte_only);
TEST (spi_flash_test_write_flash_1_1_2_3byte_4byte);
TEST (spi_flash_test_write_flash_1_2_2_3byte_4byte);
TEST (spi_flash_test_write_flash_2_2_2_3byte_4byte);
TEST (spi_flash_test_write_flash_1_1_4_3byte_4byte);
TEST (spi_flash_test_write_flash_1_4_4_3byte_4byte);
TEST (spi_flash_test_write_flash_4_4_4_3byte_4byte);
TEST (spi_flash_test_write_flag_status_register);
TEST (spi_flash_test_write_static);
TEST (spi_flash_test_write_static_read_only);
TEST (spi_flash_test_write_null);
TEST (spi_flash_test_write_out_of_range);
TEST (spi_flash_test_write_too_long);
TEST (spi_flash_test_write_error_enable);
TEST (spi_flash_test_write_error_write);
TEST (spi_flash_test_write_error_second_page);
TEST (spi_flash_test_write_error_in_progress);
TEST (spi_flash_test_write_error_in_progress_flag_status_register);
TEST (spi_flash_test_write_status_error);
TEST (spi_flash_test_sector_erase);
TEST (spi_flash_test_sector_erase_offset_address);
TEST (spi_flash_test_sector_erase_max_address);
TEST (spi_flash_test_sector_erase_4byte);
TEST (spi_flash_test_sector_erase_flash_api);
TEST (spi_flash_test_sector_erase_switch_4byte_address);
TEST (spi_flash_test_sector_erase_flash_1_1_1_3byte_only);
TEST (spi_flash_test_sector_erase_flash_1_1_1_3byte_4byte);
TEST (spi_flash_test_sector_erase_flash_1_1_1_4byte_only);
TEST (spi_flash_test_sector_erase_flash_1_1_2_3byte_4byte);
TEST (spi_flash_test_sector_erase_flash_1_2_2_3byte_4byte);
TEST (spi_flash_test_sector_erase_flash_2_2_2_3byte_4byte);
TEST (spi_flash_test_sector_erase_flash_1_1_4_3byte_4byte);
TEST (spi_flash_test_sector_erase_flash_1_4_4_3byte_4byte);
TEST (spi_flash_test_sector_erase_flash_4_4_4_3byte_4byte);
TEST (spi_flash_test_sector_erase_flag_status_register);
TEST (spi_flash_test_sector_erase_static);
TEST (spi_flash_test_sector_erase_static_read_only);
TEST (spi_flash_test_sector_erase_null);
TEST (spi_flash_test_sector_erase_out_of_range);
TEST (spi_flash_test_sector_erase_error_enable);
TEST (spi_flash_test_sector_erase_error_in_progress);
TEST (spi_flash_test_sector_erase_error_in_progress_flag_status_register);
TEST (spi_flash_test_sector_erase_status_error);
TEST (spi_flash_test_sector_erase_error);
TEST (spi_flash_test_sector_erase_wait_error);
TEST (spi_flash_test_block_erase);
TEST (spi_flash_test_block_erase_offset_address);
TEST (spi_flash_test_block_erase_max_address);
TEST (spi_flash_test_block_erase_4byte);
TEST (spi_flash_test_block_erase_flash_api);
TEST (spi_flash_test_block_erase_switch_4byte_address);
TEST (spi_flash_test_block_erase_flash_1_1_1_3byte_only);
TEST (spi_flash_test_block_erase_flash_1_1_1_3byte_4byte);
TEST (spi_flash_test_block_erase_flash_1_1_1_4byte_only);
TEST (spi_flash_test_block_erase_flash_1_1_2_3byte_4byte);
TEST (spi_flash_test_block_erase_flash_1_2_2_3byte_4byte);
TEST (spi_flash_test_block_erase_flash_2_2_2_3byte_4byte);
TEST (spi_flash_test_block_erase_flash_1_1_4_3byte_4byte);
TEST (spi_flash_test_block_erase_flash_1_4_4_3byte_4byte);
TEST (spi_flash_test_block_erase_flash_4_4_4_3byte_4byte);
TEST (spi_flash_test_block_erase_flag_status_register);
TEST (spi_flash_test_block_erase_static);
TEST (spi_flash_test_block_erase_static_read_only);
TEST (spi_flash_test_block_erase_null);
TEST (spi_flash_test_block_erase_out_of_range);
TEST (spi_flash_test_block_erase_error_enable);
TEST (spi_flash_test_block_erase_error_in_progress);
TEST (spi_flash_test_block_erase_error_in_progress_flag_status_register);
TEST (spi_flash_test_block_erase_status_error);
TEST (spi_flash_test_block_erase_error);
TEST (spi_flash_test_block_erase_wait_error);
TEST (spi_flash_test_chip_erase);
TEST (spi_flash_test_chip_erase_flash_api);
TEST (spi_flash_test_chip_erase_flag_status_register);
TEST (spi_flash_test_chip_erase_static);
TEST (spi_flash_test_chip_erase_static_read_only);
TEST (spi_flash_test_chip_erase_null);
TEST (spi_flash_test_chip_erase_error_enable);
TEST (spi_flash_test_chip_erase_error_in_progress);
TEST (spi_flash_test_chip_erase_error_in_progress_flag_status_register);
TEST (spi_flash_test_chip_erase_status_error);
TEST (spi_flash_test_chip_erase_error);
TEST (spi_flash_test_chip_erase_wait_error);
TEST (spi_flash_test_get_sector_size);
TEST (spi_flash_test_get_sector_size_flash_api);
TEST (spi_flash_test_get_sector_size_static_read_only);
TEST (spi_flash_test_get_sector_size_null);
TEST (spi_flash_test_get_block_size);
TEST (spi_flash_test_get_block_size_flash_api);
TEST (spi_flash_test_get_block_size_static_read_only);
TEST (spi_flash_test_get_block_size_null);
TEST (spi_flash_test_get_page_size);
TEST (spi_flash_test_get_page_size_flash_api);
TEST (spi_flash_test_get_page_size_static_read_only);
TEST (spi_flash_test_get_page_size_null);
TEST (spi_flash_test_minimum_write_per_page);
TEST (spi_flash_test_minimum_write_per_page_flash_api);
TEST (spi_flash_test_minimum_write_per_page_static_read_only);
TEST (spi_flash_test_minimum_write_per_page_null);
TEST (spi_flash_test_is_write_in_progress);
TEST (spi_flash_test_is_write_in_progress_no_write);
TEST (spi_flash_test_is_write_in_progress_flag_status_register);
TEST (spi_flash_test_is_write_in_progress_no_write_flag_status_register);
TEST (spi_flash_test_is_write_in_progress_error);
TEST (spi_flash_test_is_write_in_progress_null);
TEST (spi_flash_test_wait_for_write);
TEST (spi_flash_test_wait_for_write_flag_status_register);
TEST (spi_flash_test_wait_for_write_null);
TEST (spi_flash_test_wait_for_write_timeout);
TEST (spi_flash_test_wait_for_write_immediate_timeout);
TEST (spi_flash_test_wait_for_write_no_timeout);
TEST (spi_flash_test_wait_for_write_error);
TEST (spi_flash_test_enable_quad_spi_no_quad_enable);
TEST (spi_flash_test_enable_quad_spi_no_quad_enable_hold_disable_flag_status_register);
TEST (spi_flash_test_enable_quad_spi_no_quad_enable_hold_disable_volatile_write_enable);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_volatile_write_enable);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_no_clear);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_no_clear_volatile_write_enable);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_read_35);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_read_35_volatile_write_enable);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit6_sr1);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit6_sr1_volatile_write_enable);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit7_sr2);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit7_sr2_volatile_write_enable);
TEST (spi_flash_test_enable_quad_spi_null);
TEST (spi_flash_test_enable_quad_spi_quad_enable_bit1_sr2_read_35_sr2_read_error);
TEST (spi_flash_test_enable_quad_spi_quad_enable_read_reg_error);
TEST (spi_flash_test_enable_quad_spi_quad_enable_error_in_progress);
TEST (spi_flash_test_enable_quad_spi_quad_enable_error_in_progress_flag_status_register);
TEST (spi_flash_test_enable_quad_spi_quad_enable_write_reg_error);
TEST (spi_flash_test_is_quad_spi_enabled_no_quad_enable);
TEST (spi_flash_test_is_quad_spi_enabled_no_quad_enable_hold_disable);
TEST (spi_flash_test_is_quad_spi_enabled_quad_enable_bit1_sr2);
TEST (spi_flash_test_is_quad_spi_enabled_quad_enable_bit1_sr2_no_clear);
TEST (spi_flash_test_is_quad_spi_enabled_quad_enable_bit1_sr2_read_35);
TEST (spi_flash_test_is_quad_spi_enabled_quad_enable_bit6_sr1);
TEST (spi_flash_test_is_quad_spi_enabled_quad_enable_bit7_sr2);
TEST (spi_flash_test_is_quad_spi_enabled_null);
TEST (spi_flash_test_is_quad_spi_enabled_read_reg_error);
TEST (spi_flash_test_clear_block_protect_no_quad_enable);
TEST (spi_flash_test_clear_block_protect_no_quad_enable_hold_disable);
TEST (spi_flash_test_clear_block_protect_quad_enable_bit1_sr2);
TEST (spi_flash_test_clear_block_protect_quad_enable_bit1_sr2_no_clear);
TEST (spi_flash_test_clear_block_protect_quad_enable_bit1_sr2_read_35);
TEST (spi_flash_test_clear_block_protect_quad_enable_bit6_sr1);
TEST (spi_flash_test_clear_block_protect_quad_enable_bit7_sr2);
TEST (spi_flash_test_clear_block_protect_volatile_write_enable);
TEST (spi_flash_test_clear_block_protect_flag_status_register);
TEST (spi_flash_test_clear_block_protect_already_clear);
TEST (spi_flash_test_clear_block_protect_already_clear_quad_enable_bit6_sr1);
TEST (spi_flash_test_clear_block_protect_microchip);
TEST (spi_flash_test_clear_block_protect_null);
TEST (spi_flash_test_clear_block_protect_error_id);
TEST (spi_flash_test_clear_block_protect_error_read);
TEST (spi_flash_test_clear_block_protect_error_write);
TEST (spi_flash_test_clear_block_protect_error_read_35);
TEST (spi_flash_test_clear_block_protect_error_microchip);
TEST (spi_flash_test_deep_power_down_enter);
TEST (spi_flash_test_deep_power_down_enter_discover_params);
TEST (spi_flash_test_deep_power_down_enter_not_supported);
TEST (spi_flash_test_deep_power_down_enter_static);
TEST (spi_flash_test_deep_power_down_release);
TEST (spi_flash_test_deep_power_down_release_discover_params);
TEST (spi_flash_test_deep_power_down_release_not_supported);
TEST (spi_flash_test_deep_power_down_release_static);
TEST (spi_flash_test_deep_power_down_nonstandard_opcodes);
TEST (spi_flash_test_deep_power_down_null);
TEST (spi_flash_test_deep_power_down_enter_error);
TEST (spi_flash_test_deep_power_down_release_error);
TEST (spi_flash_test_configure_drive_strength_winbond);
TEST (spi_flash_test_configure_drive_strength_winbond_set_correctly);
TEST (spi_flash_test_configure_drive_strength_no_operation);
TEST (spi_flash_test_configure_drive_strength_null);
TEST (spi_flash_test_configure_drive_strength_id_error);
TEST (spi_flash_test_configure_drive_strength_read_config_error);
TEST (spi_flash_test_configure_drive_strength_write_config_error);
TEST (spi_flash_test_configure_drive_strength_read_back_error);
TEST (spi_flash_test_configure_drive_strength_config_mismatch);
TEST (spi_flash_test_initialize_device_3byte_only);
TEST (spi_flash_test_initialize_device_3byte_4byte);
TEST (spi_flash_test_initialize_device_4byte_only);
TEST (spi_flash_test_initialize_device_1_1_4_read_3byte_only);
TEST (spi_flash_test_initialize_device_1_4_4_read_3byte_4byte);
TEST (spi_flash_test_initialize_device_1_2_2_read_4byte_only);
TEST (spi_flash_test_initialize_device_fast_read);
TEST (spi_flash_test_initialize_device_wake_device);
TEST (spi_flash_test_initialize_device_reset_device);
TEST (spi_flash_test_initialize_device_drive_strength);
TEST (spi_flash_test_initialize_device_wake_reset_and_drive_strength);
TEST (spi_flash_test_initialize_device_wip_set);
TEST (spi_flash_test_initialize_device_init_error);
TEST (spi_flash_test_initialize_device_init_fast_read_error);
TEST (spi_flash_test_initialize_device_wake_error);
TEST (spi_flash_test_initialize_device_id_error);
TEST (spi_flash_test_initialize_device_sfdp_error);
TEST (spi_flash_test_initialize_device_parameters_error);
TEST (spi_flash_test_initialize_device_wip_error);
TEST (spi_flash_test_initialize_device_reset_error);
TEST (spi_flash_test_initialize_device_drive_strength_error);
TEST (spi_flash_test_initialize_device_address_mode_error);
TEST (spi_flash_test_initialize_device_qspi_error);
TEST (spi_flash_test_initialize_device_clear_protect_error);
TEST (spi_flash_test_initialize_device_id_ff);
TEST (spi_flash_test_initialize_device_id_00);
TEST (spi_flash_test_initialize_device_state_3byte_only);
TEST (spi_flash_test_initialize_device_state_3byte_4byte);
TEST (spi_flash_test_initialize_device_state_4byte_only);
TEST (spi_flash_test_initialize_device_state_1_1_4_read_3byte_only);
TEST (spi_flash_test_initialize_device_state_1_4_4_read_3byte_4byte);
TEST (spi_flash_test_initialize_device_state_1_2_2_read_4byte_only);
TEST (spi_flash_test_initialize_device_state_fast_read);
TEST (spi_flash_test_initialize_device_state_wake_device);
TEST (spi_flash_test_initialize_device_state_reset_device);
TEST (spi_flash_test_initialize_device_state_drive_strength);
TEST (spi_flash_test_initialize_device_state_wake_reset_and_drive_strength);
TEST (spi_flash_test_initialize_device_state_wip_set);
TEST (spi_flash_test_initialize_device_state_init_error);
TEST (spi_flash_test_initialize_device_state_init_fast_read_error);
TEST (spi_flash_test_initialize_device_state_wake_error);
TEST (spi_flash_test_initialize_device_state_id_error);
TEST (spi_flash_test_initialize_device_state_sfdp_error);
TEST (spi_flash_test_initialize_device_state_parameters_error);
TEST (spi_flash_test_initialize_device_state_wip_error);
TEST (spi_flash_test_initialize_device_state_reset_error);
TEST (spi_flash_test_initialize_device_state_drive_strength_error);
TEST (spi_flash_test_initialize_device_state_address_mode_error);
TEST (spi_flash_test_initialize_device_state_qspi_error);
TEST (spi_flash_test_initialize_device_state_clear_protect_error);
TEST (spi_flash_test_initialize_device_state_id_ff);
TEST (spi_flash_test_initialize_device_state_id_00);
TEST (spi_flash_test_save_device_info);
TEST (spi_flash_test_save_device_info_initialized_device);
TEST (spi_flash_test_save_device_info_with_mode_bytes);
TEST (spi_flash_test_save_device_info_initialized_device_3byte_4byte_write_enable);
TEST (spi_flash_test_save_device_info_flag_status_register_volatile_write_enable);
TEST (spi_flash_test_save_device_info_nonstandard_deep_powerdown);
TEST (spi_flash_test_save_device_info_null);
TEST (spi_flash_test_restore_device);
TEST (spi_flash_test_restore_device_fast_read);
TEST (spi_flash_test_restore_device_4byte_write_erase);
TEST (spi_flash_test_restore_device_3byte_4byte_write_enable);
TEST (spi_flash_test_restore_device_flag_status_register_volatile_write_enable);
TEST (spi_flash_test_restore_device_nonstandard_deep_powerdown);
TEST (spi_flash_test_restore_device_null);
TEST (spi_flash_test_restore_device_fast_read_init_error);
TEST (spi_flash_test_restore_device_state);
TEST (spi_flash_test_restore_device_state_fast_read);
TEST (spi_flash_test_restore_device_state_4byte_write_erase);
TEST (spi_flash_test_restore_device_state_3byte_4byte_write_enable);
TEST (spi_flash_test_restore_device_state_flag_status_register_volatile_write_enable);
TEST (spi_flash_test_restore_device_state_nonstandard_deep_powerdown);
TEST (spi_flash_test_restore_device_state_null);
TEST (spi_flash_test_restore_device_state_fast_read_init_error);
TEST (spi_flash_test_is_address_mode_fixed);
TEST (spi_flash_test_is_address_mode_fixed_16M);
TEST (spi_flash_test_is_address_mode_fixed_3byte_only);
TEST (spi_flash_test_is_address_mode_fixed_3byte_4byte);
TEST (spi_flash_test_is_address_mode_fixed_4byte_only);
TEST (spi_flash_test_is_address_mode_fixed_null);
TEST (spi_flash_test_address_mode_requires_write_enable);
TEST (spi_flash_test_address_mode_requires_write_enable_16M);
TEST (spi_flash_test_address_mode_requires_write_enable_with_write_enable);
TEST (spi_flash_test_address_mode_requires_write_enable_3byte_only);
TEST (spi_flash_test_address_mode_requires_write_enable_3byte_4byte);
TEST (spi_flash_test_address_mode_requires_write_enable_4byte_only);
TEST (spi_flash_test_address_mode_requires_write_enable_null);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_macronix);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_winbond);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_micron);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_unknown);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_16M);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_3byte_only);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_4byte_only);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_null);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_error_id);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_error_read_reg_winbond);
TEST (spi_flash_test_is_4byte_address_mode_on_reset_error_read_reg_micron);
TEST (spi_flash_test_set_read_command);
TEST (spi_flash_test_set_read_command_null);
TEST (spi_flash_test_set_write_command);
TEST (spi_flash_test_set_write_command_null);

TEST_SUITE_END;
