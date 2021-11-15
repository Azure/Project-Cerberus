// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "testing.h"
#include "host_fw/host_state_manager.h"
#include "flash/flash_common.h"
#include "testing/mock/flash/flash_mock.h"
#include "testing/mock/host_fw/host_state_observer_mock.h"


TEST_SUITE_LABEL ("host_state_manager");


/*******************
 * Test cases
 *******************/

static void host_state_manager_test_init (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.base.nv_state);
	CuAssertIntEquals (test, 0x41, manager.base.volatile_state);

	CuAssertPtrNotNull (test, manager.base.get_active_manifest);
	CuAssertPtrNotNull (test, manager.base.save_active_manifest);
	CuAssertPtrNotNull (test, manager.base.restore_default_state);
	CuAssertPtrNotNull (test, manager.base.is_manifest_valid);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_init_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (NULL, &flash.base, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_init (&manager, NULL, 0x10000);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void host_state_manager_test_init_not_sector_aligned (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10100);
	CuAssertIntEquals (test, STATE_MANAGER_NOT_SECTOR_ALIGNED, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);
}

static void host_state_manager_test_get_read_only_flash_cs0 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_read_only_flash_cs1 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_read_only_flash_no_state (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_read_only_flash_null (CuTest *test)
{
	spi_filter_cs ro;

	TEST_START;

	ro = host_state_manager_get_read_only_flash (NULL);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);
}

static void host_state_manager_test_save_read_only_flash_cs0 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_read_only_flash, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash (&manager, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_read_only_flash_cs1 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff81, 0xff81, 0xff81, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_read_only_flash, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = host_state_manager_save_read_only_flash (&manager, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_read_only_flash_unknown_cs (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash (&manager, (spi_filter_cs) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_read_only_flash_same_cs (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_read_only_flash, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash (&manager, SPI_FILTER_CS_1);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_read_only_flash_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash (&manager, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_read_only_flash_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_read_only_flash (NULL, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_inactive_dirty_not_dirty (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_inactive_dirty_dirty (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_inactive_dirty_no_state (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_inactive_dirty_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (NULL);
	CuAssertIntEquals (test, false, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_not_dirty (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = host_state_manager_save_inactive_dirty (&manager, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_dirty (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	status = host_state_manager_save_inactive_dirty (&manager, true);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_same_state (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = host_state_manager_save_inactive_dirty (&manager, true);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_dirty_with_prevalidated_flash (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_run_time_validation, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	status = host_state_manager_save_inactive_dirty (&manager, true);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_dirty_with_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff82, 0xff82, 0xff82, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_run_time_validation, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	status = host_state_manager_save_inactive_dirty (&manager, true);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_not_dirty_with_prevalidated_flash (
	CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	status = host_state_manager_save_inactive_dirty (&manager, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_not_dirty_with_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	status = host_state_manager_save_inactive_dirty (&manager, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = host_state_manager_save_inactive_dirty (&manager, false);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_inactive_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_inactive_dirty_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_save_inactive_dirty (NULL, true);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_active_pfm_region1 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff84, 0xff84, 0xff84, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_active_pfm_region2 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_active_pfm_no_state (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_active_pfm_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (NULL, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_pfm_region1 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_active_pfm, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.base.save_active_manifest (&manager.base, 0, MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_pfm_region2 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff84, 0xff84, 0xff84, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_active_pfm, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = manager.base.save_active_manifest (&manager.base, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_pfm_unknown_region (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.base.save_active_manifest (&manager.base, 0, (enum manifest_region) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_pfm_same_region (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_active_pfm, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.base.save_active_manifest (&manager.base, 0, MANIFEST_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_pfm_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum manifest_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_2, active);

	status = manager.base.save_active_manifest (&manager.base, 0, MANIFEST_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = manager.base.get_active_manifest (&manager.base, 0);
	CuAssertIntEquals (test, MANIFEST_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_pfm_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.save_active_manifest (NULL, 0, MANIFEST_REGION_1);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_manifest_valid (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.is_manifest_valid (&manager.base, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_manifest_valid_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;
	int status;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = manager.base.is_manifest_valid (NULL, 0);
	CuAssertIntEquals (test, 0, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_pfm_dirty (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_pfm_dirty_null (CuTest *test)
{
	bool dirty;

	TEST_START;

	dirty = host_state_manager_is_pfm_dirty (NULL);
	CuAssertIntEquals (test, true, dirty);
}

static void host_state_manager_test_set_pfm_dirty (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_pfm_dirty, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_pfm_dirty, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_set_pfm_dirty (&manager, false);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_set_pfm_dirty (&manager, true);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_pfm_dirty_dirty_with_prevalidated_flash (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_pfm_dirty, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_pfm_dirty (&manager, true);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_pfm_dirty_dirty_with_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_pfm_dirty, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_run_time_validation, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_pfm_dirty (&manager, true);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_pfm_dirty_not_dirty_with_prevalidated_flash (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_pfm_dirty, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_pfm_dirty (&manager, false);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_pfm_dirty_not_dirty_with_prevalidated_flash_and_pfm (
	CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_pfm_dirty, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_pfm_dirty (&manager, false);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_pfm_dirty_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	bool dirty;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	host_state_manager_set_pfm_dirty (&manager, false);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, false, dirty);

	host_state_manager_set_pfm_dirty (&manager, true);

	dirty = host_state_manager_is_pfm_dirty (&manager);
	CuAssertIntEquals (test, true, dirty);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_pfm_dirty_null (CuTest *test)
{
	TEST_START;

	host_state_manager_set_pfm_dirty (NULL, false);
}

static void host_state_manager_test_get_run_time_validation (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_run_time_validation_null (CuTest *test)
{
	enum host_state_prevalidated validation;

	TEST_START;

	validation = host_state_manager_get_run_time_validation (NULL);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);
}

static void host_state_manager_test_set_run_time_validation (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_run_time_validation, &observer, 0,
		MOCK_ARG (&manager));
	status = mock_expect (&observer.mock, observer.base.on_run_time_validation, &observer, 0,
		MOCK_ARG (&manager));
	status = mock_expect (&observer.mock, observer.base.on_run_time_validation, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_NONE);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_run_time_validation_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum host_state_prevalidated validation;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH, validation);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH_AND_PFM);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_FLASH_AND_PFM, validation);

	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_NONE);

	validation = host_state_manager_get_run_time_validation (&manager);
	CuAssertIntEquals (test, HOST_STATE_PREVALIDATED_NONE, validation);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_run_time_validation_null (CuTest *test)
{
	TEST_START;

	host_state_manager_set_run_time_validation (NULL, HOST_STATE_PREVALIDATED_FLASH);
}

static void host_state_manager_test_get_active_recovery_image_region1 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_active_recovery_image_region2 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_active_recovery_image_no_state (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_get_active_recovery_image_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= flash_mock_expect_erase_flash_sector_verify (&flash, 0x10000, 0x1000);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (NULL);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_recovery_image_region1 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_active_recovery_image, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = host_state_manager_save_active_recovery_image (&manager, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_recovery_image_region2 (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_active_recovery_image, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = host_state_manager_save_active_recovery_image (&manager, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_recovery_image_unknown_region (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = host_state_manager_save_active_recovery_image (&manager,
		(enum recovery_image_region) 10);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_recovery_image_same_region (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_active_recovery_image, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = host_state_manager_save_active_recovery_image (&manager, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_recovery_image_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_2, active);

	status = host_state_manager_save_active_recovery_image (&manager, RECOVERY_IMAGE_REGION_1);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_save_active_recovery_image_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff88, 0xff88, 0xff88, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	enum recovery_image_region active;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = host_state_manager_save_active_recovery_image (NULL, RECOVERY_IMAGE_REGION_2);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	active = host_state_manager_get_active_recovery_image (&manager);
	CuAssertIntEquals (test, RECOVERY_IMAGE_REGION_1, active);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_restore_default_state (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.base.volatile_state);

	host_state_manager_set_pfm_dirty (&manager, false);
	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_active_pfm, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_read_only_flash, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_active_recovery_image, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_pfm_dirty, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_run_time_validation, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_bypass_mode, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_unsupported_flash, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	status = manager.base.restore_default_state (&manager.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.base.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_restore_default_state_no_change (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xffbf, 0xffbf, 0xffbf, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffbf, manager.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.base.volatile_state);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_active_pfm, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_read_only_flash, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_inactive_dirty, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_active_recovery_image, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_pfm_dirty, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_run_time_validation, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_bypass_mode, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_unsupported_flash, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	status = manager.base.restore_default_state (&manager.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.base.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_restore_default_state_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.base.volatile_state);

	host_state_manager_set_pfm_dirty (&manager, false);
	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	status = manager.base.restore_default_state (&manager.base);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xffff, manager.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.base.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_restore_default_state_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);
	CuAssertIntEquals (test, 0xff80, manager.base.nv_state);
	CuAssertIntEquals (test, 0x01, manager.base.volatile_state);

	host_state_manager_set_pfm_dirty (&manager, false);
	host_state_manager_set_run_time_validation (&manager, HOST_STATE_PREVALIDATED_FLASH);

	status = manager.base.restore_default_state (NULL);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);
	CuAssertIntEquals (test, 0xff80, manager.base.nv_state);
	CuAssertIntEquals (test, 0x02, manager.base.volatile_state);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_bypass_mode (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&manager);
	CuAssertIntEquals (test, false, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_bypass_mode_null (CuTest *test)
{
	bool bypass;

	TEST_START;

	bypass = host_state_manager_is_bypass_mode (NULL);
	CuAssertIntEquals (test, false, bypass);
}

static void host_state_manager_test_set_bypass_mode (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_bypass_mode, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_bypass_mode, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&manager);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_bypass_mode (&manager, true);

	status = host_state_manager_is_bypass_mode (&manager);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_bypass_mode (&manager, false);

	status = host_state_manager_is_bypass_mode (&manager);
	CuAssertIntEquals (test, false, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_bypass_mode_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_bypass_mode (&manager);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_bypass_mode (&manager, true);

	status = host_state_manager_is_bypass_mode (&manager);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_bypass_mode (&manager, false);

	status = host_state_manager_is_bypass_mode (&manager);
	CuAssertIntEquals (test, false, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_bypass_mode_null (CuTest *test)
{
	TEST_START;

	host_state_manager_set_bypass_mode (NULL, true);
}

static void host_state_manager_test_is_flash_supported (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_flash_supported (&manager);
	CuAssertIntEquals (test, true, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_is_flash_supported_null (CuTest *test)
{
	bool bypass;

	TEST_START;

	bypass = host_state_manager_is_flash_supported (NULL);
	CuAssertIntEquals (test, true, bypass);
}

static void host_state_manager_test_set_unsupported_flash (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&observer.mock, observer.base.on_unsupported_flash, &observer, 0,
		MOCK_ARG (&manager));
	status |= mock_expect (&observer.mock, observer.base.on_unsupported_flash, &observer, 0,
		MOCK_ARG (&manager));

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_flash_supported (&manager);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_unsupported_flash (&manager, true);

	status = host_state_manager_is_flash_supported (&manager);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_unsupported_flash (&manager, false);

	status = host_state_manager_is_flash_supported (&manager);
	CuAssertIntEquals (test, true, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_unsupported_flash_no_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_is_flash_supported (&manager);
	CuAssertIntEquals (test, true, status);

	host_state_manager_set_unsupported_flash (&manager, true);

	status = host_state_manager_is_flash_supported (&manager);
	CuAssertIntEquals (test, false, status);

	host_state_manager_set_unsupported_flash (&manager, false);

	status = host_state_manager_is_flash_supported (&manager);
	CuAssertIntEquals (test, true, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_set_unsupported_flash_null (CuTest *test)
{
	TEST_START;

	host_state_manager_set_unsupported_flash (NULL, true);
}

static void host_state_manager_test_add_observer_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (NULL, &observer.base);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_add_observer (&manager, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_remove_observer (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_remove_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash (&manager, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}

static void host_state_manager_test_remove_observer_null (CuTest *test)
{
	struct flash_mock flash;
	struct host_state_observer_mock observer;
	struct host_state_manager manager;
	int status;
	uint16_t state[4] = {0xff80, 0xff80, 0xff80, 0};
	uint16_t end[4] = {0xffff, 0xffff, 0xffff, 0xffff};
	spi_filter_cs ro;
	uint32_t bytes = FLASH_SECTOR_SIZE;

	TEST_START;

	status = flash_mock_init (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_init (&observer);
	CuAssertIntEquals (test, 0, status);

	status = mock_expect (&flash.mock, flash.base.get_sector_size, &flash, 0, MOCK_ARG_NOT_NULL);
	status |= mock_expect_output (&flash.mock, 0, &bytes, sizeof (bytes), -1);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x11000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10000),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, state, sizeof (state), 2);

	status |= mock_expect (&flash.mock, flash.base.read, &flash, 0, MOCK_ARG (0x10008),
		MOCK_ARG_NOT_NULL, MOCK_ARG(8));
	status |= mock_expect_output (&flash.mock, 1, end, sizeof (end), 2);

	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_init (&manager, &flash.base, 0x10000);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_add_observer (&manager, &observer.base);
	CuAssertIntEquals (test, 0, status);

	status = host_state_manager_remove_observer (NULL, &observer.base);
	CuAssertIntEquals (test, STATE_MANAGER_INVALID_ARGUMENT, status);

	status = host_state_manager_remove_observer (&manager, NULL);
	CuAssertIntEquals (test, OBSERVABLE_INVALID_ARGUMENT, status);

	status = mock_expect (&observer.mock, observer.base.on_read_only_flash, &observer, 0,
		MOCK_ARG (&manager));
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_1, ro);

	status = host_state_manager_save_read_only_flash (&manager, SPI_FILTER_CS_0);
	CuAssertIntEquals (test, 0, status);

	ro = host_state_manager_get_read_only_flash (&manager);
	CuAssertIntEquals (test, SPI_FILTER_CS_0, ro);

	status = flash_mock_validate_and_release (&flash);
	CuAssertIntEquals (test, 0, status);

	status = host_state_observer_mock_validate_and_release (&observer);
	CuAssertIntEquals (test, 0, status);

	host_state_manager_release (&manager);
}


TEST_SUITE_START (host_state_manager);

TEST (host_state_manager_test_init);
TEST (host_state_manager_test_init_null);
TEST (host_state_manager_test_init_not_sector_aligned);
TEST (host_state_manager_test_get_read_only_flash_cs0);
TEST (host_state_manager_test_get_read_only_flash_cs1);
TEST (host_state_manager_test_get_read_only_flash_no_state);
TEST (host_state_manager_test_get_read_only_flash_null);
TEST (host_state_manager_test_save_read_only_flash_cs0);
TEST (host_state_manager_test_save_read_only_flash_cs1);
TEST (host_state_manager_test_save_read_only_flash_unknown_cs);
TEST (host_state_manager_test_save_read_only_flash_same_cs);
TEST (host_state_manager_test_save_read_only_flash_no_observer);
TEST (host_state_manager_test_save_read_only_flash_null);
TEST (host_state_manager_test_is_inactive_dirty_not_dirty);
TEST (host_state_manager_test_is_inactive_dirty_dirty);
TEST (host_state_manager_test_is_inactive_dirty_no_state);
TEST (host_state_manager_test_is_inactive_dirty_null);
TEST (host_state_manager_test_save_inactive_dirty_not_dirty);
TEST (host_state_manager_test_save_inactive_dirty_dirty);
TEST (host_state_manager_test_save_inactive_dirty_same_state);
TEST (host_state_manager_test_save_inactive_dirty_dirty_with_prevalidated_flash);
TEST (host_state_manager_test_save_inactive_dirty_dirty_with_prevalidated_flash_and_pfm);
TEST (host_state_manager_test_save_inactive_dirty_not_dirty_with_prevalidated_flash);
TEST (host_state_manager_test_save_inactive_dirty_not_dirty_with_prevalidated_flash_and_pfm);
TEST (host_state_manager_test_save_inactive_dirty_no_observer);
TEST (host_state_manager_test_save_inactive_dirty_null);
TEST (host_state_manager_test_get_active_pfm_region1);
TEST (host_state_manager_test_get_active_pfm_region2);
TEST (host_state_manager_test_get_active_pfm_no_state);
TEST (host_state_manager_test_get_active_pfm_null);
TEST (host_state_manager_test_save_active_pfm_region1);
TEST (host_state_manager_test_save_active_pfm_region2);
TEST (host_state_manager_test_save_active_pfm_unknown_region);
TEST (host_state_manager_test_save_active_pfm_same_region);
TEST (host_state_manager_test_save_active_pfm_no_observer);
TEST (host_state_manager_test_save_active_pfm_null);
TEST (host_state_manager_test_is_manifest_valid);
TEST (host_state_manager_test_is_manifest_valid_null);
TEST (host_state_manager_test_is_pfm_dirty);
TEST (host_state_manager_test_is_pfm_dirty_null);
TEST (host_state_manager_test_set_pfm_dirty);
TEST (host_state_manager_test_set_pfm_dirty_dirty_with_prevalidated_flash);
TEST (host_state_manager_test_set_pfm_dirty_dirty_with_prevalidated_flash_and_pfm);
TEST (host_state_manager_test_set_pfm_dirty_not_dirty_with_prevalidated_flash);
TEST (host_state_manager_test_set_pfm_dirty_not_dirty_with_prevalidated_flash_and_pfm);
TEST (host_state_manager_test_set_pfm_dirty_no_observer);
TEST (host_state_manager_test_set_pfm_dirty_null);
TEST (host_state_manager_test_get_run_time_validation);
TEST (host_state_manager_test_get_run_time_validation_null);
TEST (host_state_manager_test_set_run_time_validation);
TEST (host_state_manager_test_set_run_time_validation_no_observer);
TEST (host_state_manager_test_set_run_time_validation_null);
TEST (host_state_manager_test_get_active_recovery_image_region1);
TEST (host_state_manager_test_get_active_recovery_image_region2);
TEST (host_state_manager_test_get_active_recovery_image_no_state);
TEST (host_state_manager_test_get_active_recovery_image_null);
TEST (host_state_manager_test_save_active_recovery_image_region1);
TEST (host_state_manager_test_save_active_recovery_image_region2);
TEST (host_state_manager_test_save_active_recovery_image_unknown_region);
TEST (host_state_manager_test_save_active_recovery_image_same_region);
TEST (host_state_manager_test_save_active_recovery_image_no_observer);
TEST (host_state_manager_test_save_active_recovery_image_null);
TEST (host_state_manager_test_restore_default_state);
TEST (host_state_manager_test_restore_default_state_no_change);
TEST (host_state_manager_test_restore_default_state_no_observer);
TEST (host_state_manager_test_restore_default_state_null);
TEST (host_state_manager_test_is_bypass_mode);
TEST (host_state_manager_test_is_bypass_mode_null);
TEST (host_state_manager_test_set_bypass_mode);
TEST (host_state_manager_test_set_bypass_mode_no_observer);
TEST (host_state_manager_test_set_bypass_mode_null);
TEST (host_state_manager_test_is_flash_supported);
TEST (host_state_manager_test_is_flash_supported_null);
TEST (host_state_manager_test_set_unsupported_flash);
TEST (host_state_manager_test_set_unsupported_flash_no_observer);
TEST (host_state_manager_test_set_unsupported_flash_null);
TEST (host_state_manager_test_add_observer_null);
TEST (host_state_manager_test_remove_observer);
TEST (host_state_manager_test_remove_observer_null);

TEST_SUITE_END;
