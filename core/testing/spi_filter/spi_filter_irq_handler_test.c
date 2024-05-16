// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "flash/spi_flash.h"
#include "host_fw/host_state_manager.h"
#include "spi_filter/spi_filter_irq_handler.h"
#include "spi_filter/spi_filter_irq_handler_static.h"
#include "state_manager/state_manager.h"
#include "testing/mock/flash/flash_master_mock.h"
#include "testing/mock/spi_filter/spi_filter_interface_mock.h"


TEST_SUITE_LABEL ("spi_filter_irq_handler");


/**
 * Initialize the host state manager for testing.
 *
 * @param test The testing framework.
 * @param state The host state instance to initialize.
 * @param flash_mock The mock for the flash state storage.
 * @param flash The flash device to initialize for state.
 * @param flash_state Variable context for the flash device.
 */
static void spi_filter_irq_handler_testing_init_host_state (CuTest *test,
	struct host_state_manager *state, struct flash_master_mock *flash_mock, struct spi_flash *flash,
	struct spi_flash_state *flash_state)
{
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};

	status = flash_master_mock_init (flash_mock);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_init (flash, flash_state, &flash_mock->base);
	CuAssertIntEquals (test, 0, status);

	status = spi_flash_set_device_size (flash, 0x1000000);
	CuAssertIntEquals (test, 0, status);

	status = flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, (uint8_t*) end, sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x10000, 0, -1, 8));

	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, &WIP_STATUS, 1,
		FLASH_EXP_READ_STATUS_REG);
	status |= flash_master_mock_expect_rx_xfer (flash_mock, 0, (uint8_t*) end, sizeof (end),
		FLASH_EXP_READ_CMD (0x03, 0x11000, 0, -1, 8));

	status |= flash_master_mock_expect_erase_flash_sector_verify (flash_mock, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (state, &flash->base, 0x10000);
	CuAssertIntEquals (test, 0, status);
}


/*******************
 * Test cases
 *******************/

static void spi_filter_irq_handler_test_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler;
	int status;

	TEST_START;

	spi_filter_irq_handler_testing_init_host_state (test, &host_state, &flash_mock, &flash, &state);

	status = spi_filter_irq_handler_init (&handler, &host_state);
	CuAssertIntEquals (test, 0, status);

	CuAssertPtrNotNull (test, handler.ro_flash_dirty);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_filter_irq_handler_release (&handler);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash);
}

static void spi_filter_irq_handler_test_init_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler;
	int status;

	TEST_START;

	spi_filter_irq_handler_testing_init_host_state (test, &host_state, &flash_mock, &flash, &state);

	status = spi_filter_irq_handler_init (NULL, &host_state);
	CuAssertIntEquals (test, SPI_FILTER_IRQ_INVALID_ARGUMENT, status);

	status = spi_filter_irq_handler_init (&handler, NULL);
	CuAssertIntEquals (test, SPI_FILTER_IRQ_INVALID_ARGUMENT, status);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash);
}

static void spi_filter_irq_handler_test_static_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler = spi_filter_irq_handler_static_init (&host_state);
	int status;

	TEST_START;

	CuAssertPtrNotNull (test, handler.ro_flash_dirty);

	spi_filter_irq_handler_testing_init_host_state (test, &host_state, &flash_mock, &flash, &state);

	spi_filter_irq_handler_release (&handler);

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash);
}

static void spi_filter_irq_handler_test_release_null (CuTest *test)
{
	TEST_START;

	spi_filter_irq_handler_release (NULL);
}

static void spi_filter_irq_handler_test_ro_flash_dirty (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler;
	int status;

	TEST_START;

	spi_filter_irq_handler_testing_init_host_state (test, &host_state, &flash_mock, &flash, &state);

	status = spi_filter_irq_handler_init (&handler, &host_state);
	CuAssertIntEquals (test, 0, status);

	handler.ro_flash_dirty (&handler);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_filter_irq_handler_release (&handler);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash);
}

static void spi_filter_irq_handler_test_ro_flash_dirty_static_init (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler = spi_filter_irq_handler_static_init (&host_state);
	int status;

	TEST_START;

	spi_filter_irq_handler_testing_init_host_state (test, &host_state, &flash_mock, &flash, &state);

	handler.ro_flash_dirty (&handler);

	CuAssertIntEquals (test, true, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_filter_irq_handler_release (&handler);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash);
}

static void spi_filter_irq_handler_test_ro_flash_dirty_null (CuTest *test)
{
	struct flash_master_mock flash_mock;
	struct spi_flash_state state;
	struct spi_flash flash;
	struct host_state_manager host_state;
	struct spi_filter_irq_handler handler;
	int status;

	TEST_START;

	spi_filter_irq_handler_testing_init_host_state (test, &host_state, &flash_mock, &flash, &state);

	status = spi_filter_irq_handler_init (&handler, &host_state);
	CuAssertIntEquals (test, 0, status);

	handler.ro_flash_dirty (NULL);

	CuAssertIntEquals (test, false, host_state_manager_is_inactive_dirty (&host_state));

	status = flash_master_mock_validate_and_release (&flash_mock);
	CuAssertIntEquals (test, 0, status);

	spi_filter_irq_handler_release (&handler);

	host_state_manager_release (&host_state);
	spi_flash_release (&flash);
}


// *INDENT-OFF*
TEST_SUITE_START (spi_filter_irq_handler);

TEST (spi_filter_irq_handler_test_init);
TEST (spi_filter_irq_handler_test_init_null);
TEST (spi_filter_irq_handler_test_static_init);
TEST (spi_filter_irq_handler_test_release_null);
TEST (spi_filter_irq_handler_test_ro_flash_dirty);
TEST (spi_filter_irq_handler_test_ro_flash_dirty_static_init);
TEST (spi_filter_irq_handler_test_ro_flash_dirty_null);

TEST_SUITE_END;
// *INDENT-ON*
